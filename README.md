# Attack Graph Analysis com BFS 🛡️🕸️

Este projeto é uma implementação em Python de um **Grafo de Ataque (Attack Graph)** aplicado à segurança de redes. Ele utiliza o algoritmo de **Busca em Largura (BFS)** para identificar o *Caminho de Ataque Mínimo* (Minimum Attack Path), ou seja, a rota com o menor número de explorações de vulnerabilidades necessárias para que um atacante comprometa um ativo crítico.

Este repositório serve como implementação prática de conceitos teóricos de Teoria dos Grafos aplicados à Cibersegurança.

## 📋 Funcionalidades

- **Modelagem de Rede:** Criação de nós (ativos/estados) e arestas (exploits/vulnerabilidades).
- **Algoritmo BFS:** Encontra o caminho mais curto garantido em grafos não ponderados.
- **Visualização Gráfica:** Gera automaticamente uma imagem (`.png`) da rede destacando a rota do ataque em vermelho.

## 🚀 Como executar

### Pré-requisitos

Você precisa ter o Python 3.8+ instalado.
Você precisa de networkx e matplotlib
