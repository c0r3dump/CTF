# SpamAndFlags 2020 - TAS

## Challenge

Time to take a break from CTFing and play some [videogames](handout.tar.gz)! How fast can you complete it??

Checker server: `nc 35.242.182.148 1337`

136+158+166+181+199+384 points, solved the first three (136+158+166).

## Solution

### Adding TAS features to game

I decided to start by adding some TAS features to the game, somewhat limited by my lack of python knowledge:

* Frame advance (left shift)
* Max speed replay playback
* Continue replay at end as game
* Record replay of replay to accompany previous feature

Here's a diff for these features:

```diff
diff --git a/Game.py b/Game.py
index 8d1281b..91b7a08 100644
--- a/Game.py
+++ b/Game.py
@@ -42,9 +42,8 @@ class Game(object):
 
   def __del__(self):
     pygame.quit()
-    if (self.mode == "game"):
-      self.writeReplayFile("../replay.txt")
-      print("Wrote replay input to replay.txt", flush=True)
+    self.writeReplayFile("../replay.txt")
+    print("Wrote replay input to replay.txt", flush=True)
 
   def loadReplay(self):
     result = []
@@ -93,14 +92,16 @@ class Game(object):
         if event.type == pygame.locals.QUIT:
           return False
 
-    self.input.tick(events)
+    if self.input.tick(events) != True:
+        return True
+    
     for sprite in self.tickGroup.sprites():
       sprite.tick()
     self.map.tick()
     self.renderer.render()
 
     if self.mode != "check":
-      self.fpsClock.tick(Game.FPS)
+      self.fpsClock.tick(6000 if self.input.mode != "game" else Game.FPS)
 
     if self.won() or self.died() or self.reachedEndOfReplay():
       return False
diff --git a/Input.py b/Input.py
index 33cacb4..c25ac01 100644
--- a/Input.py
+++ b/Input.py
@@ -19,21 +19,24 @@ class KeysPressed():
 
 class Input(object):
 
-  def __init__(self, mode, replay):
+  def __init__(self, mode, inreplay):
     self.mode = mode
-    self.replay = replay
+    self.inreplay = inreplay
+    self.replay = []
     self.keysPressed = KeysPressed()
     self.pos = 0
     self.prev_progress = 0
 
   def tick(self, events):
     if self.mode == "game":
-      self.readInputFromKeyboard(events)
+      return self.readInputFromKeyboard(events)
     else:
       self.readInputFromReplay()
+      return True
 
   def readInputFromKeyboard(self, events):
     prevLeft = self.keysPressed.left
+    advance = False
     for event in events:
       if event.type == locals.KEYUP or event.type == locals.KEYDOWN:
         pressed = (event.type == locals.KEYDOWN)
@@ -47,29 +50,43 @@ class Input(object):
           self.keysPressed.right = pressed
         if event.key == locals.K_SPACE:
           self.keysPressed.space = pressed
+        if event.key == locals.K_LSHIFT and event.type == locals.KEYDOWN:
+          advance = True
 
+    if advance != True:
+      return False
+    
     # If both directions are pressed, use whichever was pressed most recently.
     if self.keysPressed.left and self.keysPressed.right:
       if prevLeft:
         self.keysPressed.left = False
       else:
         self.keysPressed.right = False
+    
+    #if self.keysPressed.asNumber() == 0:
+      #return False
 
     self.replay.append(copy(self.keysPressed))
+    
+    return True
 
   def readInputFromReplay(self):
-    keys = self.replay[self.pos] if self.pos < len(self.replay)  else 0
+    keys = self.inreplay[self.pos] if self.pos < len(self.inreplay)  else 0
     self.pos += 1
     self.keysPressed = KeysPressed(keys)
+    self.replay.append(copy(self.keysPressed))
     if self.mode == "check":
-      progress = round(self.pos / len(self.replay) * 100)
+      progress = round(self.pos / len(self.inreplay) * 100)
       if self.prev_progress != progress:
         print("%d%%" % progress, flush=True)
         self.prev_progress = progress
 
 
   def reachedEndOfReplay(self):
-    return self.mode != "game" and self.pos >= len(self.replay)
+    #return self.mode != "game" and self.pos >= len(self.inreplay)
+    if self.mode != "game" and self.pos >= len(self.inreplay):
+        self.mode = "game"
+    return False;
 
   def getKeysPressed(self):
     return copy(self.keysPressed)
```

### Bugs abused

The only bug abused was crouching cancelling attack cooldown to kill enemies faster.

### Getting the flags

To get the first 3 flags, we need to send the generated `replay.txt` to the server.

```txt
user@ubuntu:~/handout$ cat replay.txt - | nc 35.242.182.148 1337 
Input replay file + empty line

checking...
1%
2%
3%
4%
5%
6%
7%
8%
9%
10%
11%
12%
13%
14%
15%
16%
17%
18%
19%
20%
21%
22%
23%
24%
25%
26%
27%
28%
29%
30%
31%
32%
33%
34%
35%
36%
37%
38%
39%
40%
41%
42%
43%
44%
45%
46%
47%
48%
49%
50%
51%
52%
53%
54%
55%
56%
57%
58%
59%
60%
61%
62%
63%
64%
65%
66%
67%
68%
69%
70%
71%
72%
73%
74%
75%
76%
77%
78%
79%
80%
81%
82%
83%
84%
85%
86%
87%
88%
89%
90%
91%
92%
93%
94%
95%
96%
97%
98%
99%
100%
WON!
Your time: 1941 frames
You beat the game! Here's flag number 0:
SaF{N1ce!_N0w_m4ke_Y0uRs3lF_a_t0Ol_t0_ASs15t_yoU}
You beat the game under 2250 frames! Here's flag number 1:
SaF{GrE4t!_N0w_1Ts_tIm3_tO_F1nd_s0ME_Gl1tcH3s}
You beat the game under 2020 frames! Here's flag number 2:
SaF{WHen_y0Ur_InT3RNet_cONneCTioN_1s_g0Od_TR3x_SpENd5_h15_fR3e_T1mE_GU4rDinG_Fl4Gs}
Now try completing it under 1790 frames!
```

Flag 1: `SaF{N1ce!_N0w_m4ke_Y0uRs3lF_a_t0Ol_t0_ASs15t_yoU}`

Flag 2: `SaF{GrE4t!_N0w_1Ts_tIm3_tO_F1nd_s0ME_Gl1tcH3s}`
 
Flag 3: `SaF{WHen_y0Ur_InT3RNet_cONneCTioN_1s_g0Od_TR3x_SpENd5_h15_fR3e_T1mE_GU4rDinG_Fl4Gs}`

### Files

* [video](tas.webm)
* [replay](replay.txt)

## Other write-ups

- <https://ctftime.org/task/11525>
