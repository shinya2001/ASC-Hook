#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>

int areAllVisited(int visited[], int size)
{
    for (int i = 0; i < size; i++)
    {
        if (visited[i] == 0)
            return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    
    int size, rank;
    double start_time, end_time, elapsed_time;
    int source_vertex;
    int no_of_vertices;
    int *visited = (int *)malloc(sizeof(int) * 40000);

    
    MPI_Init(&argc, &argv);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    pid_t pid = getpid();
    printf("pid = %d\n", pid);
    sleep(2);
    if (rank == 0)
    {
        start_time = MPI_Wtime();
    }

    
    FILE *input = fopen("adjacency_matrix.txt", "r");
    if (input == NULL)
    {
        printf("can't open adjacency_matrix.txt\n");
        MPI_Finalize();
        return 1;
    }

    fscanf(input, "%d", &no_of_vertices);  

    int rows_per_process = no_of_vertices / size; 
    if (rank == 0)
    {
        printf("Number of rows per process: %d\n", rows_per_process); 
    }

    int *adjacency_matrix = (int *)malloc(rows_per_process * no_of_vertices * sizeof(int));  
    int *bfs_traversal = (int *)malloc(no_of_vertices * no_of_vertices * sizeof(int));  

    int start_row = rank * rows_per_process + 1;     
    int end_row = (rank + 1) * rows_per_process + 1; 

    const char *filename = "adjacency_matrix.txt"; 

    
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Unable to open file %s\n", filename);
        MPI_Finalize();
        return 1;
    }

    for (int i = 0; i < start_row; ++i)
    {
        char buffer[100000];
        fgets(buffer, sizeof(buffer), file);
    }

    int p = 0;

    for (int i = start_row; i < end_row; ++i)
    {
        for (int j = 0; j < no_of_vertices; j++)
        {
            fscanf(file, "%d", &adjacency_matrix[p]);
            p++;
        }
    }
    printf("\n");

   
    int *adjacency_queue = (int *)malloc(rows_per_process * no_of_vertices * sizeof(int));

    for (int i = 0; i < rows_per_process * no_of_vertices; i++)
    {
        adjacency_queue[i] = -1;
    }

    // BFS code
    int index = 0;
    int changed = 0;
    for (int i = 0; i < rows_per_process * no_of_vertices; i++)
    {
        if (adjacency_matrix[i] == 1)
        {
            adjacency_queue[index++] = i % no_of_vertices;
        }
    }

    MPI_Barrier(MPI_COMM_WORLD); 


    MPI_Gather(adjacency_queue, rows_per_process * no_of_vertices, MPI_INT, bfs_traversal, rows_per_process * no_of_vertices, MPI_INT, 0, MPI_COMM_WORLD);

    // Printing the Order of traversed nodes in root
    for (int i = 0; i < no_of_vertices; i++)
    {
        visited[i] = 0;
    }

    if (rank == 0)
    {
        end_time = MPI_Wtime();
        elapsed_time = end_time - start_time;

        printf("\nBFS Traversal:\n");
        printf("%d \n", source_vertex);
        printf("0");
        for (int i = 0; i < no_of_vertices * no_of_vertices; i++)
        {
            if (areAllVisited(visited, no_of_vertices))
            {
                break;
            }

            if (bfs_traversal[i] != -1)
            {
                if (visited[bfs_traversal[i]] == 0 && bfs_traversal[i] != source_vertex)
                {
                    if (bfs_traversal[i] == 0)
                    {
                        continue;
                    }
                    printf(" -> %d", bfs_traversal[i]);
                    visited[bfs_traversal[i]] = 1;
                }
            }
            else
            {
                continue;
            }
        }
        printf("\nTotal elapsed time = %f seconds\n", elapsed_time);
    }

    // Free heap memory
    free(adjacency_matrix);
    free(bfs_traversal);
    free(adjacency_queue);
    // End of BFS code
    MPI_Finalize();
    printf("\n");
    return 0;
}
