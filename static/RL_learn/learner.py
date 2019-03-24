import random
import pickle
import sys
import ctypes

if __name__ == "__main__":
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

class Learner:
    def __init__(self, alpha=0.3, epsilon=0.2, gamma=0.9):
        self.alpha = alpha
        self.epsilon = epsilon
        self.gamma = gamma
        self.V = {}
        self.last_state = None
        self.v_last = 0
        self.last_action = None

    def new_game(self):
        self.last_state = None
        self.v_last = 0
        self.last_action = None

    def make_move(self, state):
        possible_moves = [tile for tile, t in enumerate(state) if t == ' ']
        self.last_state = tuple(state)
        if random.random() < self.epsilon:
            move = random.choice(possible_moves)
        else:
            movesV = []
            for move in possible_moves:
                movesV.append((self.getV(self.last_state, move), move))
            maxV = max([value for value, move in movesV])
            best_moves = [move for value, move in movesV if value == maxV]
            move = random.choice(best_moves)
        self.last_action = (self.last_state, move)
        self.v_last = self.getV(*self.last_action)
        return move

    def getV(self, state, action):
        if (state, action) not in self.V:
            self.V[(state, action)] = 0
        return self.V[(state, action)]

    def updateV(self, state, reward):
        possible_moves = [tile for tile, t in enumerate(state) if t == ' ']
        maxV = 0.0
        if possible_moves:
            maxV = max([self.getV(tuple(state), move) for move in possible_moves])
        self.V[self.last_action] = self.v_last + self.alpha * ((reward + self.gamma * maxV) - self.v_last)

    def save_states(self, name):
        with open(name, 'wb') as f:
            pickle.dump(self.V, f, protocol=pickle.HIGHEST_PROTOCOL)

    def load_states(self, name):
        with open(name, 'rb') as f:
            self.V = pickle.load(f)

class Game:
    def __init__(self):
        self.board = [' ']*9
    
    def reset(self):
        self.board = [' ']*9

    def do_move(self, isX, move):
        if isX:
            self.board[move] = 'X'
        else:
            self.board[move] = 'O'
        reward, done = self.evaluate_state()
        # if reward == 1:
        #     print('X' if isX else 'O', 'wins!')
        # elif reward == 0.5:
        #     print('Draw')
        return (reward, done)

    def evaluate_state(self):
        for i in range(3):
            if self.board[i*3] != ' ': 
                if self.board[i*3] == self.board[i*3+1] and self.board[i*3] == self.board[i*3+2]:
                    return 1, True
            if self.board[i] != ' ':
                if self.board[i] == self.board[i+3] and self.board[i] == self.board[i+6]:
                    return 1, True
        if self.board[4] != ' ':
            if self.board[0] == self.board[4] and self.board[0] == self.board[8]:
                return 1, True
            if self.board[2] == self.board[4] and self.board[2] == self.board[6]:
                return 1, True
        if len([tile for tile, t in enumerate(self.board) if t == ' ']) < 1:
            return 0.5, True
        return 0.0, False

    def get_player_move(self, player_char):
        place = 0
        place = int(input('where do you wanna play an {}?: '.format(player_char)))
        while place > 0 and place < 10 and self.board[place - 1] != ' ':
            place = int(input('invalid choice, where do you wanna place a {}?: '.format(player_char)))
        return place - 1
                    

    def play(self):
        player_char = None
        while player_char is None:
            player_choice = input('who do you wanna play as?: ')
            if player_choice == 'X':
                player_char = 'X'
            elif player_choice == 'O':
                player_char = 'O'
        agent = Learner(epsilon=0)
        if player_char == 'X':
            agent.load_states('playero.pickle')
        if player_char == 'O':
            agent.load_states('playerx.pickle')
        xturn = True # random.choice([True, False]) 
        done = False
        self.draw_board()
        while not done:
            if xturn:
                if player_char == 'X':
                    move = self.get_player_move(player_char)
                else:
                    print('agent turn')
                    move = agent.make_move(self.board)
            else:
                if player_char == 'O':
                    move = self.get_player_move(player_char)
                else:
                    print('agent turn')
                    move = agent.make_move(self.board)
            reward, done = self.do_move(xturn, move)

            self.draw_board()

            if reward == 1:
                if xturn and player_char == 'O' or not xturn and player_char == 'X':
                    print('Agent Wins')
                    agent.updateV(self.board, reward)
                else:
                    print('You Win!')
                    agent.updateV(self.board, 0)
            if reward == 0.5:
                print('Draw')
                agent.updateV(self.board, reward)
            else:
                if xturn and player_char == 'X' or not xturn and player_char == 'O':
                    agent.updateV(self.board, reward)
            xturn = not xturn




        
    def draw_board(self):
        print('\n |{}|{}|{}| \n---------\n |{}|{}|{}| \n---------\n |{}|{}|{}| \n'.format(*self.board))

    def start_train(self):
        playerX = Learner()
        playerO = Learner()
        xwin = 0
        owin = 0
        draw = 0
        for i in range(400000):
            self.reset()
            playerX.new_game()
            playerO.new_game()
            xturn = random.choice([True, False])
            done = False
            while not done:
                if xturn:
                    move = playerX.make_move(self.board)
                else:
                    move = playerO.make_move(self.board)
                reward, done = self.do_move(xturn, move)

                if reward == 1:
                    if xturn:
                        xwin += 1
                        playerX.updateV(self.board, reward)
                        playerO.updateV(self.board, 0)
                    else:
                        owin += 1
                        playerX.updateV(self.board, 0)
                        playerO.updateV(self.board, reward)
                elif reward == 0.5:
                    draw += 1
                    playerX.updateV(self.board, reward)
                    playerO.updateV(self.board, reward)
                else:
                    if xturn:
                        playerO.updateV(self.board, reward)
                    else:
                        playerX.updateV(self.board, reward)
                xturn = not xturn
            sys.stdout.write('\x1b[2Kgame {}: {}, x wins: {}, o wins: {}, draws: {}\r'.format(i + 1, 'Draw!' if reward == 0.5 else 'X Wins!' if xturn else 'O Wins!', xwin, owin, draw))
        playerX.save_states('playerx.pickle')
        playerO.save_states('playero.pickle') 

if __name__ == '__main__':    
    game = Game()
    game.start_train()
    # game.play()

    # with open('playerx.pickle', 'rb') as f:
    #     print(pickle.load(f))
