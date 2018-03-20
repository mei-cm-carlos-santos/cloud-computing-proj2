import { NgModule }      from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpModule } from '@angular/http';
import { FormsModule, ReactiveFormsModule }   from '@angular/forms';

import { AppComponent }  from './app.component';
import { HomeComponent }  from './general/home.component';
import { ErrorComponent }  from './general/error.component';
import { LoginComponent }   from './auth/login.component';
import { RegisterComponent }   from './auth/register.component';
import { ChangePasswordComponent }   from './auth/changepassword.component';
import { LobbyComponent }   from './lobby/lobby.component';
import { GamesDataComponent }   from './data-view/games.data.component';
import { TopComponent }   from './data-view/top.component';
import { GamesComponent }   from './game/games.component';
import { GameComponent }   from './game/game.component';

import { AppRoutingModule }     from './routes/app-routing.module';

import { RestGameService } from './services/rest.game.service';
import { RestAuthService } from './services/rest.auth.service';
import { UserSecurityService } from './services/security.service';
import { WebSocketService } from './services/websocket.service';
import { AuthGuard } from './services/auth.guard.service';
import {Global} from './services/global.service'

@NgModule({
  imports:      [ 
    BrowserModule,
    AppRoutingModule,
    HttpModule,
    FormsModule,
    ReactiveFormsModule
  ],
  declarations: [ 
    AppComponent,
    HomeComponent,
    ErrorComponent,
    LoginComponent,
    RegisterComponent,
    ChangePasswordComponent,
    LobbyComponent,
    GamesDataComponent,
    TopComponent,
    GamesComponent,
    GameComponent
  ],
  providers:    [ 
    RestAuthService, 
    RestGameService, 
    UserSecurityService, 
    AuthGuard,
    Global,
    WebSocketService ],
  bootstrap:    [ AppComponent ]
})
export class AppModule { }
