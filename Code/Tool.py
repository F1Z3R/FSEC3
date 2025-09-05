import detector
import rule_generator
import retraining

ASCII_BANNER = r"""
                ********  ********  ********    ******      
                /**/////  **//////  /**/////   **////**    
                /**      /**        /**       **    //          
                /******* /********* /******* /**           
                /**////  ////////** /**////  /**             
                /**             /** /**      //**    **     
                /**       ********  /******** //******    
                //       ////////   ////////   //////        

**********************************************************************
*                                                                    *
*            FSEC – AI Malicious Flow Detection & Rule Gen           *
*                            Made by F1Z3R                           *
*                 © 2025 F1Z3R. All Rights Reserved.                 *
*                                                                    *
**********************************************************************
"""

def main():
    print(ASCII_BANNER)
    while True:
        print("\n================= Main Menu =================")
        print("1 - Detector")
        print("2 - Rule Generator")
        print("3 - Retraining")
        print("0 - Exit")
        print("=============================================")

        choice = input("Enter your choice: ").strip()
        print("------------------------------------------------------------")

        if choice == '1':
            print("\n********** Running Detector **********\n")
            detector.run_detection()
        elif choice == '2':
            print("\n********** Running Rule Generator **********\n")
            rule_generator.generate_rules()
        elif choice == '3':
            print("\n********** Running Retraining **********\n")
            retraining.retrain_model()
        elif choice == '0':
            print("Exiting the tool. Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
