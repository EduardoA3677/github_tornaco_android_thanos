.class public final Llyiahf/vczjk/tm1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animationState:Llyiahf/vczjk/oaa;

.field final synthetic $bringIntoViewSpec:Llyiahf/vczjk/gi0;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/um1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/um1;Llyiahf/vczjk/oaa;Llyiahf/vczjk/gi0;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tm1;->this$0:Llyiahf/vczjk/um1;

    iput-object p2, p0, Llyiahf/vczjk/tm1;->$animationState:Llyiahf/vczjk/oaa;

    iput-object p3, p0, Llyiahf/vczjk/tm1;->$bringIntoViewSpec:Llyiahf/vczjk/gi0;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/tm1;

    iget-object v1, p0, Llyiahf/vczjk/tm1;->this$0:Llyiahf/vczjk/um1;

    iget-object v2, p0, Llyiahf/vczjk/tm1;->$animationState:Llyiahf/vczjk/oaa;

    iget-object v3, p0, Llyiahf/vczjk/tm1;->$bringIntoViewSpec:Llyiahf/vczjk/gi0;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/tm1;-><init>(Llyiahf/vczjk/um1;Llyiahf/vczjk/oaa;Llyiahf/vczjk/gi0;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/tm1;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tm1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tm1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/tm1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/tm1;->label:I

    const/4 v2, 0x1

    const/4 v3, 0x0

    const/4 v4, 0x0

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto :goto_2

    :catch_0
    move-exception v0

    move-object p1, v0

    move-object v4, p1

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/tm1;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->OoooOOo(Llyiahf/vczjk/or1;)Llyiahf/vczjk/v74;

    move-result-object v9

    :try_start_1
    iget-object v7, p0, Llyiahf/vczjk/tm1;->this$0:Llyiahf/vczjk/um1;

    iput-boolean v2, v7, Llyiahf/vczjk/um1;->Oooo0O0:Z

    iget-object p1, v7, Llyiahf/vczjk/um1;->OooOoo0:Llyiahf/vczjk/db8;

    sget-object v1, Llyiahf/vczjk/at5;->OooOOO0:Llyiahf/vczjk/at5;

    new-instance v5, Llyiahf/vczjk/sm1;

    iget-object v6, p0, Llyiahf/vczjk/tm1;->$animationState:Llyiahf/vczjk/oaa;

    iget-object v8, p0, Llyiahf/vczjk/tm1;->$bringIntoViewSpec:Llyiahf/vczjk/gi0;

    const/4 v10, 0x0

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/sm1;-><init>(Llyiahf/vczjk/oaa;Llyiahf/vczjk/um1;Llyiahf/vczjk/gi0;Llyiahf/vczjk/v74;Llyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/tm1;->label:I

    invoke-virtual {p1, v1, v5, p0}, Llyiahf/vczjk/db8;->OooO0o0(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/tm1;->this$0:Llyiahf/vczjk/um1;

    iget-object p1, p1, Llyiahf/vczjk/um1;->OooOooo:Llyiahf/vczjk/sh0;

    invoke-virtual {p1}, Llyiahf/vczjk/sh0;->OooO0O0()V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    iget-object p1, p0, Llyiahf/vczjk/tm1;->this$0:Llyiahf/vczjk/um1;

    iput-boolean v3, p1, Llyiahf/vczjk/um1;->Oooo0O0:Z

    iget-object p1, p1, Llyiahf/vczjk/um1;->OooOooo:Llyiahf/vczjk/sh0;

    invoke-virtual {p1, v4}, Llyiahf/vczjk/sh0;->OooO00o(Ljava/util/concurrent/CancellationException;)V

    iget-object p1, p0, Llyiahf/vczjk/tm1;->this$0:Llyiahf/vczjk/um1;

    iput-boolean v3, p1, Llyiahf/vczjk/um1;->Oooo00O:Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_1
    :try_start_2
    throw v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/tm1;->this$0:Llyiahf/vczjk/um1;

    iput-boolean v3, v0, Llyiahf/vczjk/um1;->Oooo0O0:Z

    iget-object v0, v0, Llyiahf/vczjk/um1;->OooOooo:Llyiahf/vczjk/sh0;

    invoke-virtual {v0, v4}, Llyiahf/vczjk/sh0;->OooO00o(Ljava/util/concurrent/CancellationException;)V

    iget-object v0, p0, Llyiahf/vczjk/tm1;->this$0:Llyiahf/vczjk/um1;

    iput-boolean v3, v0, Llyiahf/vczjk/um1;->Oooo00O:Z

    throw p1
.end method
