import { NgModule }             from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { HomeComponent }   from '../general/home.component';
import { ErrorComponent }   from '../general/error.component';
import { LoginComponent }   from '../auth/login.component';
import { RegisterComponent }   from '../auth/register.component';
import { ChangePasswordComponent }   from '../auth/changepassword.component';
import { LobbyComponent }   from '../lobby/lobby.component';
import { GamesDataComponent }   from '../data-view/games.data.component';
import { TopComponent }   from '../data-view/top.component';
import { GamesComponent }   from '../game/games.component';

import { AuthGuard } from '../services/auth.guard.service';


const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home',  component: HomeComponent },
  { path: 'error',  component: ErrorComponent },
  { path: 'login',  component: LoginComponent },
  { path: 'register',  component: RegisterComponent },  
  { path: 'gamesdata/:t', component: GamesDataComponent, canActivate: [AuthGuard] },
  { path: 'top',  component: TopComponent },
  { path: 'lobby',  component: LobbyComponent, canActivate: [AuthGuard] },
  { path: 'games',  component: GamesComponent, canActivate: [AuthGuard] },
  { path: 'changepassword',  component: ChangePasswordComponent, canActivate: [AuthGuard]  },
];


@NgModule({
  imports: [ RouterModule.forRoot(routes) ],
  exports: [ RouterModule ]
})
export class AppRoutingModule {}
