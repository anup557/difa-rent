"""
x_i_s, x_i_(s-1),....x_i_0 denote the input to the (i+1)-th round for version 64, 128 resp. 
"""

from gurobipy import *
import time

class Cipher:
    def __init__(self, Round, active_bit_set, cipher_name):
        self.Round = Round
        self.active_bit_set = active_bit_set

        self.version = 128			
        self.name = cipher_name			

        self.filename_model = "./lp/" + str(self.name) + "_"  + str(self.Round) + "_" + str(len(self.active_bit_set)) + ".lp"
        self.filename_result = "./result/result_" + str(self.name) + "_" + str(self.Round) + "_" + str(len(self.active_bit_set)) + ".txt"
        fileobj = open(self.filename_model, "w")
        fileobj.close()
        fileboj = open(self.filename_result, "w")
        fileobj.close()

    # Linear inequalities for the default Sbox
    S_T=[[1, 1, 1, 1, -1, -1, -1, -1, 0],\
    [-1, -2, -2, -1, 2, 1, 2, 1, 1],\
    [1, -1, 5, 1, -3, -2, -3, -2, 4],\
    [1, 5, -1, 1, -3, -2, -3, -2, 4],\
    [-1, 0, 0, -1, 1, 1, 1, 1, 0],\
    [-1, -2, -2, -1, 1, 1, 1, 1, 2],\
    [0, 0, 1, 1, -1, -1, -1, 0, 1],\
    [1, 0, 1, 0, -1, 0, -1, -1, 1],\
    [1, 0, 0, -2, 1, -1, 1, 2, 1],\
    [-1, 0, 0, 0, 1, 1, 1, 0, 0]]


    # NUMBER is number of coefficients. Here first 4 bits are for input 4 bits of sbox, second 4-bits are for output bits of sbox and 1 for rightside of inequality.
    NUMBER = 9		

    def CreateObjectiveFunction(self):
        """
        Create objective function of the MILP model
        """
        fileobj = open(self.filename_model, "a")
        fileobj.write("Minimize\n")
        eqn = []
        for i in range(0, self.version):
            eqn.append("x" + "_" + str(self.Round) + "_" + str(i))
        temp = " + ".join(eqn)
        fileobj.write(temp)
        fileobj.write("\n")
        fileobj.close()

    # @staticmethod
    def CreateVariables(self, n):
        """
        Generate the variables used in the model.
        """
        array = []
        for i in range(0, self.version):
            array.append(("x" + "_" + str(n) + "_" + str(i)))
        return array

    def ConstraintsBySbox(self, variable1, variable2):
        """
        Generate the constraints by sbox layer.
        """
        fileobj = open(self.filename_model,"a")

        # sbox_range is for total no. of sbox, as that varries over the version
        sbox_range = int((self.version)/4)

        # this for loop takes 4-bit input and 4-bit output of each sbox and replace that with the equations of the sbox  
        for k in range(0, sbox_range):
            for coff in Cipher.S_T:
                temp = []
                for u in range(0,4):
                    temp.append(str(coff[u]) + " " + variable1[(k * 4) + 3 - u])
                for v in range(0,4):
                    temp.append(str(coff[v + 4]) + " " + variable2[(k * 4) + 3 - v])
                temp1 = " + ".join(temp)
                temp1 = temp1.replace("+ -", "- ")
                s = str(-coff[Cipher.NUMBER - 1])
                s = s.replace("--", "")
                temp1 += " >= " + s
                fileobj.write(temp1)
                fileobj.write("\n")
        fileobj.close(); 

    # @staticmethod
    def LinearLayer(self, variable):
        """
        Linear layer of Cipher.
        """
        array = ["" for i in range(0, self.version)]

        # The lower lists are permutation of GIFT-128.
        array_index = [0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3, 4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7, 8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11, 12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15, 16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19, 20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23, 24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27, 28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31]

        for i in range(0, self.version):
            array[array_index[i]] = variable[i]
        
        return array


    def Constraint(self):
        """
        Generate the constraints used in the MILP model.
        """
        assert(self.Round >= 1)
        fileobj = open(self.filename_model, "a")
        fileobj.write("Subject To\n")
        fileobj.close()
        variablein = self.CreateVariables(0)
        variableout = self.CreateVariables(1)
        if self.Round == 1:
            self.ConstraintsBySbox(variablein, variableout)
            # omit the last linear layer
        else:
            self.ConstraintsBySbox(variablein, variableout)
            for i in range(1, self.Round):
                variablein = self.LinearLayer(variableout)
                variableout= self.CreateVariables(i + 1)
                self.ConstraintsBySbox(variablein, variableout)
                #omit the last linear layer

    def VariableBinary(self):
        """
        Specify the variable type.
        """
        fileobj = open(self.filename_model, "a")
        fileobj.write("Binary\n")
        for i in range(0, (self.Round + 1)):
            for j in range(0, self.version):
                fileobj.write("x_" + str(i) + "_" + str(j))
                fileobj.write("\n")
        fileobj.write("END")
        fileobj.close()

    def Init(self):
        """
        Generate the constraints introduced by the initial division property.
        """
        variableout = self.CreateVariables(0)
        fileobj = open(self.filename_model, "a")

        # depending upon active_bit_set[] it will make those positions 1
        eqn = []
        for i in range(0, self.version):
            if i in self.active_bit_set:
                temp = variableout[i] + " = 1"
                fileobj.write(temp)
                fileobj.write("\n")
            else:
                temp = variableout[i] + " = 0"
                fileobj.write(temp)
                fileobj.write("\n")
        fileobj.close()

    def MakeModel(self):
        """
        Generate the MILP model of Cipher given the round number and activebits.
        """
        self.CreateObjectiveFunction()
        self.Constraint()
        self.Init()
        self.VariableBinary()

    def WriteObjective(self, obj):
        """
        Write the objective value into filename_result.
        """
        fileobj = open(self.filename_result, "a")
        fileobj.write("The objective value = %d\n" %obj.getValue())
        eqn1 = []
        eqn2 = []
        for i in range(0, self.version):
            u = obj.getVar(i)
            if u.getAttr("x") != 0:
                eqn1.append(u.getAttr('VarName'))
                eqn2.append(u.getAttr('x'))
        length = len(eqn1)
        for i in range(0,length):
            s = eqn1[i] + "=" + str(eqn2[i])
            fileobj.write(s)
            fileobj.write("\n")
        fileobj.close()

    def SolveModel(self, fileobj_main):
    # def SolveModel(self):
        """
        Solve the MILP model to search the integral distinguisher of Cipher.
        """
        time_start = time.time()
        m = read(self.filename_model)
        counter = 0
        set_zero = []
        global_flag = False
        while counter < self.version:
            m.optimize()
            # Gurobi syntax: m.Status == 2 represents the model is feasible.
            if m.Status == 2:
                obj = m.getObjective()
                if obj.getValue() > 1:
                                global_flag = True
                                print("test")
                                break
                else:
                    fileobj = open(self.filename_result, "a")
                    fileobj.write("************************************COUNTER = %d\n" % counter)
                    fileobj.close()
                    self.WriteObjective(obj)

                    for i in range(0, self.version):
                        u = obj.getVar(i)
                        temp = u.getAttr('x')
                        if temp == 1:
                            set_zero.append(u.getAttr('VarName'))
                            u.ub = 0
                            m.update()
                            counter += 1
                            break
            # Gurobi syntax: m.Status == 3 represents the model is infeasible.
            elif m.Status == 3:
                global_flag = True
                break
            else:
                print("Unknown error!")

        
        fileobj = open(self.filename_result, "a")		
        if global_flag:
            fileobj.write("\nIntegral Distinguisher Found!\n\n")
            print("Integral Distinguisher Found!\n")
        else:
            fileobj.write("\nIntegral Distinguisher do NOT exist\n\n")
            print("Integral Distinguisher do NOT exist\n")

        # next 4 lines are to print the coordinates which are zero
        fileobj.write("Those are the coordinates set to zero: \n")
        for u in set_zero:
            fileobj.write(u)
            fileobj.write(", ")

        # next 3 lines are used to print balanced bits
        obj_var_list = []
        for i in range(0,self.version):
            obj_var_list.append(obj.getVar(i).VarName)

        # printing balanced bits
        fileobj.write("\n\nBalanced bits occurs at:\n")         
        for u in obj_var_list:
            if(u in set_zero):
                continue
            fileobj.write(u)
            fileobj.write(", ")


        # this is after varrying sbox, and writing those in main function's file. If you want to solve only for one active bit list then comment lower 6 lines and uncomment SolveModel() line.
        fileobj_main.write("\nBalanced bits occurs at:\n")         
        for u in obj_var_list:
            if(u in set_zero):
                continue
            fileobj_main.write(u)
            fileobj_main.write(", ")


        fileobj.write("\n")
        fileobj.close()

        # return the balanced bits list
        balanced_bits = [u for u in obj_var_list if u not in set_zero]
        return balanced_bits

