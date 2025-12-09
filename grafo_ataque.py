import collections
import matplotlib.pyplot as plt
import networkx as nx
from typing import List, Dict, Optional, Set, Tuple

class AttackGraph:
    """
    Representa um Grafo de Ataque em Segurança de Redes.
    Utiliza listas de adjacência para modelar estados (nós) e exploits (arestas).
    """

    def __init__(self):
        # Dicionário onde a chave é o nó origem e o valor é uma lista de tuplas (nó destino, descrição da ação)
        self.graph: Dict[str, List[Tuple[str, str]]] = collections.defaultdict(list)
        # Grafo auxiliar do NetworkX apenas para visualização
        self.visual_graph = nx.DiGraph()

    def add_attack_step(self, source: str, target: str, exploit_name: str):
        """
        Adiciona um passo de ataque (aresta) ao grafo.
        
        :param source: Estado atual (ex: 'Internet', 'User_PC')
        :param target: Estado alcançado (ex: 'Admin_Server')
        :param exploit_name: Nome da vulnerabilidade/ação usada (ex: 'SSH_Bruteforce')
        """
        self.graph[source].append((target, exploit_name))
        self.visual_graph.add_edge(source, target, label=exploit_name)
        print(f"[+] Passo adicionado: {source} --({exploit_name})--> {target}")

    def find_shortest_attack_path_bfs(self, start_node: str, target_node: str) -> Optional[List[str]]:
        """
        Executa o algoritmo BFS (Busca em Largura) para encontrar o caminho
        de ataque com o menor número de passos (exploits).
        
        :return: Lista com a sequência de nós do caminho ou None se não houver caminho.
        """
        if start_node not in self.graph and start_node not in [u for u, v in self.visual_graph.edges]:
            print(f"[-] Erro: Nó de início '{start_node}' não existe no grafo.")
            return None

        # Fila para o BFS: armazena (nó_atual, caminho_até_aqui)
        queue = collections.deque([[start_node]])
        visited = {start_node}

        print(f"\n[*] Iniciando busca BFS de '{start_node}' até '{target_node}'...")

        while queue:
            path = queue.popleft()
            current_node = path[-1]

            # Se chegamos ao alvo, retornamos o caminho
            if current_node == target_node:
                print(f"[!] Caminho encontrado com {len(path)-1} passos!")
                return path

            # Explora vizinhos
            for neighbor, exploit in self.graph[current_node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)
        
        print("[-] Nenhum caminho de ataque encontrado até o alvo.")
        return None

    def visualize_path(self, path: List[str], filename: str = "attack_path.png"):
        """
        Gera uma imagem do grafo destacando o caminho do ataque em vermelho.
        """
        if not path:
            return

        pos = nx.spring_layout(self.visual_graph, seed=42)
        plt.figure(figsize=(12, 8))

        # Desenha todos os nós e arestas em cinza (padrão)
        nx.draw(self.visual_graph, pos, with_labels=True, node_color='lightblue', 
                edge_color='gray', node_size=2000, font_size=10, font_weight='bold', arrows=True)
        
        # Desenha as descrições das arestas (exploits)
        edge_labels = nx.get_edge_attributes(self.visual_graph, 'label')
        nx.draw_networkx_edge_labels(self.visual_graph, pos, edge_labels=edge_labels, font_color='blue')

        # Destaca o caminho do ataque em vermelho
        path_edges = list(zip(path, path[1:]))
        nx.draw_networkx_nodes(self.visual_graph, pos, nodelist=path, node_color='red', node_size=2500)
        nx.draw_networkx_edges(self.visual_graph, pos, edgelist=path_edges, edge_color='red', width=2.5)

        plt.title(f"Visualização do Caminho de Ataque (BFS)\nAlvo Atingido: {path[-1]}")
        plt.savefig(filename)
        print(f"[+] Visualização salva como '{filename}'")
        plt.close()

# --- Execução Principal (Exemplo de Uso) ---
if __name__ == "__main__":
    # 1. Instancia o grafo
    attack_net = AttackGraph()

    # 2. Constrói o cenário (Topologia da Rede e Vulnerabilidades)
    # Cenário: Hacker externo tentando chegar ao Banco de Dados SQL
    
    # Camada 1: Entrada
    attack_net.add_attack_step("Internet", "WebServer", "CVE-2023-XYZ (RCE)")
    attack_net.add_attack_step("Internet", "VPN_Gateway", "Weak_Credentials")

    # Camada 2: Movimentação Lateral
    attack_net.add_attack_step("WebServer", "AppServer", "Config_Error")
    attack_net.add_attack_step("WebServer", "FileServer", "SMB_Exploit")
    attack_net.add_attack_step("VPN_Gateway", "Internal_PC", "Phishing_Link")

    # Camada 3: Profundidade
    attack_net.add_attack_step("AppServer", "Database_SQL", "SQL_Injection")
    attack_net.add_attack_step("FileServer", "Database_SQL", "Stored_Creds")
    attack_net.add_attack_step("Internal_PC", "Database_SQL", "Admin_Access")

    # Adicionando um caminho distração (mais longo)
    attack_net.add_attack_step("Internal_PC", "Printer", "Default_Password")
    attack_net.add_attack_step("Printer", "Database_SQL", "Legacy_Connect")

    # 3. Executa o algoritmo BFS
    start = "Internet"
    target = "Database_SQL"
    
    shortest_path = attack_net.find_shortest_attack_path_bfs(start, target)

    # 4. Exibe o resultado
    if shortest_path:
        print("\n" + "="*40)
        print("RELATÓRIO DE CAMINHO DE ATAQUE (MÍNIMO)")
        print("="*40)
        print(" -> ".join(shortest_path))
        print("="*40 + "\n")

        # 5. Gera visualização
        attack_net.visualize_path(shortest_path)