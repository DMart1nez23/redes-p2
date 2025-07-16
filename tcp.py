import asyncio
import math
from tcputils import *

class GerenteConexoes:
    def __init__(self, interface, porta_local):
        self.interface = interface
        self.porta_local = porta_local
        self.tabela = {}
        self.monitor = None
        self.interface.registrar_recebedor(self._receptor_interno)

    def definir_monitor_conexoes(self, monitor):
        self.monitor = monitor

    def _receptor_interno(self, origem, destino, segmento):
        src_p, dst_p, seq, ack, flags, win, cks, urg = read_header(segmento)

        if dst_p != self.porta_local:
            print(f'Ignorando pacote: porta de destino {dst_p} difere da esperada {self.porta_local}.')
            return

        if not self.interface.ignore_checksum and calc_checksum(segmento, origem, destino) != 0:
            print('Segmento descartado: falha na verificação de integridade (checksum).')
            return

        deslocamento = 4 * (flags >> 12)
        conteudo = segmento[deslocamento:]
        chave = (origem, src_p, destino, dst_p)

        if (flags & FLAGS_SYN) and chave not in self.tabela:
            print(f'Recebido SYN de {origem}:{src_p}, nova conexão criada.')
            nova_con = Sessao(self, chave, seq)
            self.tabela[chave] = nova_con

            ack += 1
            resposta = make_header(dst_p, src_p, seq, ack, FLAGS_SYN | FLAGS_ACK)
            pacote = fix_checksum(resposta, origem, destino)
            self.interface.enviar(pacote, origem)

            if self.monitor:
                print('Callback de conexão sendo chamado.')
                self.monitor(nova_con)

        elif chave in self.tabela:
            print(f'Pacote pertence à conexão existente: {chave}')
            self.tabela[chave]._receptor_interno(seq, ack, flags, conteudo)

        else:
            print(f'Pacote descartado: conexão desconhecida {chave}')

class Sessao:
    def __init__(self, gerente, chave, seq_inicial):
        self.gerente = gerente
        self.chave = chave
        self.base_seq = seq_inicial
        self.seq_atual = seq_inicial + 1
        self.ack_atual = seq_inicial + 1
        self.receptor = None
        self.temporizador = None
        self.buffer_pendente = b''

    def timeout_reenvio(self):
        if self.temporizador:
            self.temporizador.cancel()
            self.temporizador = None

        origem, p_origem, destino, p_destino = self.chave
        if self.buffer_pendente:
            cab = make_header(p_destino, p_origem, self.base_seq, self.ack_atual, FLAGS_ACK)
            pacote = fix_checksum(cab + self.buffer_pendente[:MSS], destino, origem)
            self.gerente.interface.enviar(pacote, origem)
            print(f'Reenvio: Seq={self.base_seq}, Tamanho={len(self.buffer_pendente[:MSS])}')

        self.temporizador = asyncio.get_event_loop().call_later(1, self.timeout_reenvio)

    def _receptor_interno(self, seq, ack, flags, conteudo):
        origem, p_origem, destino, p_destino = self.chave

        print(f'Pacote recebido com conteúdo: {conteudo}')

        if self.ack_atual != seq:
            return

        if flags & FLAGS_FIN:
            self.ack_atual += 1
            resposta = make_header(p_destino, p_origem, self.base_seq, self.ack_atual, FLAGS_ACK)
            pacote = fix_checksum(resposta, destino, origem)
            self.gerente.interface.enviar(pacote, origem)
            self.receptor(self, b'')
            del self.gerente.tabela[self.chave]

        self.ack_atual += len(conteudo)

        if conteudo:
            ack_resp = make_header(p_destino, p_origem, self.base_seq, self.ack_atual, FLAGS_ACK)
            pacote = fix_checksum(ack_resp, destino, origem)
            self.receptor(self, conteudo)
            self.gerente.interface.enviar(pacote, origem)
            return

        if flags & FLAGS_ACK:
            if self.temporizador:
                self.temporizador.cancel()
                self.temporizador = None

            self.buffer_pendente = self.buffer_pendente[ack - self.base_seq:]
            self.base_seq = ack

            if ack < self.seq_atual:
                self.temporizador = asyncio.get_event_loop().call_later(0.5, self.timeout_reenvio)

    def definir_receptor(self, receptor):
        self.receptor = receptor

    def transmitir(self, dados):
        origem, p_origem, destino, p_destino = self.chave
        posicao = 0

        while posicao < len(dados):
            fatia = dados[posicao:posicao + MSS]
            cab = make_header(p_destino, p_origem, self.seq_atual, self.ack_atual, FLAGS_ACK)
            pacote = fix_checksum(cab + fatia, destino, origem)

            self.gerente.interface.enviar(pacote, origem)
            print(f'Transmitindo: Seq={self.seq_atual}, Tamanho={len(fatia)}')

            self.seq_atual += len(fatia)
            self.buffer_pendente += fatia
            posicao += MSS

            if not self.temporizador:
                self.temporizador = asyncio.get_event_loop().call_later(0.5, self.timeout_reenvio)

    def encerrar(self):
        origem, p_origem, destino, p_destino = self.chave
        cab = make_header(p_destino, p_origem, self.seq_atual, self.ack_atual, FLAGS_FIN)
        pacote = fix_checksum(cab, destino, origem)

        self.gerente.interface.enviar(pacote, origem)
        print(f'Enviando FIN: Seq={self.seq_atual}, Ack={self.ack_atual}')

        if not self.temporizador:
            self.temporizador = asyncio.get_event_loop().call_later(1, self.timeout_reenvio)
