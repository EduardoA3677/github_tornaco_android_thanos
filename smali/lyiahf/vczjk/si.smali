.class public final Llyiahf/vczjk/si;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animSpec$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $animatable:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field

.field final synthetic $channel:Llyiahf/vczjk/rs0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/rs0;"
        }
    .end annotation
.end field

.field final synthetic $listener$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rs0;Llyiahf/vczjk/gi;Llyiahf/vczjk/p29;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/si;->$channel:Llyiahf/vczjk/rs0;

    iput-object p2, p0, Llyiahf/vczjk/si;->$animatable:Llyiahf/vczjk/gi;

    iput-object p3, p0, Llyiahf/vczjk/si;->$animSpec$delegate:Llyiahf/vczjk/p29;

    iput-object p4, p0, Llyiahf/vczjk/si;->$listener$delegate:Llyiahf/vczjk/p29;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/si;

    iget-object v1, p0, Llyiahf/vczjk/si;->$channel:Llyiahf/vczjk/rs0;

    iget-object v2, p0, Llyiahf/vczjk/si;->$animatable:Llyiahf/vczjk/gi;

    iget-object v3, p0, Llyiahf/vczjk/si;->$animSpec$delegate:Llyiahf/vczjk/p29;

    iget-object v4, p0, Llyiahf/vczjk/si;->$listener$delegate:Llyiahf/vczjk/p29;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/si;-><init>(Llyiahf/vczjk/rs0;Llyiahf/vczjk/gi;Llyiahf/vczjk/p29;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/si;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/si;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/si;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/si;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/si;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/si;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ej0;

    iget-object v3, p0, Llyiahf/vczjk/si;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/xr1;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/si;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object v1, p0, Llyiahf/vczjk/si;->$channel:Llyiahf/vczjk/rs0;

    invoke-interface {v1}, Llyiahf/vczjk/ui7;->iterator()Llyiahf/vczjk/ej0;

    move-result-object v1

    move-object v3, p1

    :goto_0
    iput-object v3, p0, Llyiahf/vczjk/si;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/si;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/si;->label:I

    invoke-virtual {v1, p0}, Llyiahf/vczjk/ej0;->OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_4

    invoke-virtual {v1}, Llyiahf/vczjk/ej0;->OooO0OO()Ljava/lang/Object;

    move-result-object p1

    iget-object v4, p0, Llyiahf/vczjk/si;->$channel:Llyiahf/vczjk/rs0;

    invoke-interface {v4}, Llyiahf/vczjk/ui7;->OooO0OO()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/jt0;->OooO00o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    if-nez v4, :cond_3

    move-object v6, p1

    goto :goto_2

    :cond_3
    move-object v6, v4

    :goto_2
    new-instance v5, Llyiahf/vczjk/ri;

    iget-object v7, p0, Llyiahf/vczjk/si;->$animatable:Llyiahf/vczjk/gi;

    iget-object v8, p0, Llyiahf/vczjk/si;->$animSpec$delegate:Llyiahf/vczjk/p29;

    iget-object v9, p0, Llyiahf/vczjk/si;->$listener$delegate:Llyiahf/vczjk/p29;

    const/4 v10, 0x0

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/ri;-><init>(Ljava/lang/Object;Llyiahf/vczjk/gi;Llyiahf/vczjk/p29;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    const/4 v4, 0x0

    invoke-static {v3, v4, v4, v5, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_0

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
