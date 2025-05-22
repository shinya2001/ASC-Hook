#include <stdio.h>
#include <stdlib.h>


void generateCompleteBinaryTreeAdjacencyMatrix(int numNodes, int adjMatrix[][numNodes])
{
    for (int i = 0; i < numNodes; ++i)
    {
        int leftChild = 2 * i + 1;
        int rightChild = 2 * i + 2;

        if (leftChild < numNodes)
        {
            adjMatrix[i][leftChild] = 1;
            adjMatrix[leftChild][i] = 1;
        }

        if (rightChild < numNodes)
        {
            adjMatrix[i][rightChild] = 1;
            adjMatrix[rightChild][i] = 1;
        }
    }
}

void writeMatrixToFile(int numNodes, int adjMatrix[][numNodes], const char *filename)
{
    FILE *file = fopen(filename, "w");
    if (file == NULL)
    {
        printf("Error opening file %s\n", filename);
        return;
    }

    fprintf(file, "%d\n", numNodes); // Write the number of nodes

    for (int i = 0; i < numNodes; ++i)
    {
        for (int j = 0; j < numNodes; ++j)
        {
            fprintf(file, "%d ", adjMatrix[i][j]);
        }
        fprintf(file, "\n");
    }

    fclose(file);
    printf("tree has been written %s\n", filename);
}

int main()
{
    int numNodes;
    printf("Enter the number of nodes: ");
    scanf("%d", &numNodes);

    int(*adjMatrix)[numNodes] = malloc(numNodes * sizeof(int[numNodes]));
    if (adjMatrix == NULL)
    {
        printf("memory alloc failed\n");
        return 1;
    }

    for (int i = 0; i < numNodes; ++i)
    {
        for (int j = 0; j < numNodes; ++j)
        {
            adjMatrix[i][j] = 0;
        }
    }

    generateCompleteBinaryTreeAdjacencyMatrix(numNodes, adjMatrix);
    writeMatrixToFile(numNodes, adjMatrix, "adjacency_matrix.txt");

    free(adjMatrix);

    return 0;
}
