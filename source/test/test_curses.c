#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    initscr();
    box(stdscr, ACS_VLINE, ACS_HLINE); /*draw a box*/
    move(LINES/2, COLS/2); /*move the cursor to the center*/
    waddstr(stdscr, "Hello, world!");
    int i;
    char strline[20];
    for(i=0; i<10; i++) {
        move(i, 10);
        sprintf(strline, "line: %d", i);
        waddstr(stdscr, strline);
        hline(0, 50);
    }
    refresh();

    clear();
    int size = 0;
    while(1) {
        sleep(1);
        move(50+size, 20+size);
        vline(0, size);
        size ++;
        move(LINES/2, COLS/2);
        waddstr(stdscr, "a");
        refresh();
    }
    getch();
    endwin();
    return 0;
}
