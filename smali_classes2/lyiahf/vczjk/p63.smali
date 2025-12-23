.class public final Llyiahf/vczjk/p63;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $initialValue:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $shared:Llyiahf/vczjk/os5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/os5;"
        }
    .end annotation
.end field

.field final synthetic $started:Llyiahf/vczjk/rl8;

.field final synthetic $upstream:Llyiahf/vczjk/f43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/f43;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rl8;Llyiahf/vczjk/f43;Llyiahf/vczjk/os5;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/p63;->$started:Llyiahf/vczjk/rl8;

    iput-object p2, p0, Llyiahf/vczjk/p63;->$upstream:Llyiahf/vczjk/f43;

    iput-object p3, p0, Llyiahf/vczjk/p63;->$shared:Llyiahf/vczjk/os5;

    iput-object p4, p0, Llyiahf/vczjk/p63;->$initialValue:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/p63;

    iget-object v1, p0, Llyiahf/vczjk/p63;->$started:Llyiahf/vczjk/rl8;

    iget-object v2, p0, Llyiahf/vczjk/p63;->$upstream:Llyiahf/vczjk/f43;

    iget-object v3, p0, Llyiahf/vczjk/p63;->$shared:Llyiahf/vczjk/os5;

    iget-object v4, p0, Llyiahf/vczjk/p63;->$initialValue:Ljava/lang/Object;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/p63;-><init>(Llyiahf/vczjk/rl8;Llyiahf/vczjk/f43;Llyiahf/vczjk/os5;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/p63;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p63;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/p63;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/p63;->label:I

    const/4 v2, 0x4

    const/4 v3, 0x3

    const/4 v4, 0x1

    const/4 v5, 0x2

    if-eqz v1, :cond_3

    if-eq v1, v4, :cond_2

    if-eq v1, v5, :cond_1

    if-eq v1, v3, :cond_2

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/p63;->$started:Llyiahf/vczjk/rl8;

    sget-object v1, Llyiahf/vczjk/ql8;->OooO00o:Llyiahf/vczjk/wp3;

    if-ne p1, v1, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/p63;->$upstream:Llyiahf/vczjk/f43;

    iget-object v1, p0, Llyiahf/vczjk/p63;->$shared:Llyiahf/vczjk/os5;

    iput v4, p0, Llyiahf/vczjk/p63;->label:I

    invoke-interface {p1, v1, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_7

    goto :goto_2

    :cond_4
    sget-object v1, Llyiahf/vczjk/ql8;->OooO0O0:Llyiahf/vczjk/e86;

    const/4 v4, 0x0

    if-ne p1, v1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/p63;->$shared:Llyiahf/vczjk/os5;

    check-cast p1, Llyiahf/vczjk/o00OOOOo;

    invoke-virtual {p1}, Llyiahf/vczjk/o00OOOOo;->OooOO0O()Llyiahf/vczjk/c99;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/n63;

    invoke-direct {v1, v5, v4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    iput v5, p0, Llyiahf/vczjk/p63;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/rs;->OooOoOO(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    goto :goto_2

    :cond_5
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/p63;->$upstream:Llyiahf/vczjk/f43;

    iget-object v1, p0, Llyiahf/vczjk/p63;->$shared:Llyiahf/vczjk/os5;

    iput v3, p0, Llyiahf/vczjk/p63;->label:I

    invoke-interface {p1, v1, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_7

    goto :goto_2

    :cond_6
    iget-object v1, p0, Llyiahf/vczjk/p63;->$shared:Llyiahf/vczjk/os5;

    check-cast v1, Llyiahf/vczjk/o00OOOOo;

    invoke-virtual {v1}, Llyiahf/vczjk/o00OOOOo;->OooOO0O()Llyiahf/vczjk/c99;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/rl8;->OooO0o(Llyiahf/vczjk/c99;)Llyiahf/vczjk/f43;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/rs;->OooOo0(Llyiahf/vczjk/f43;)Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/o63;

    iget-object v3, p0, Llyiahf/vczjk/p63;->$upstream:Llyiahf/vczjk/f43;

    iget-object v5, p0, Llyiahf/vczjk/p63;->$shared:Llyiahf/vczjk/os5;

    iget-object v6, p0, Llyiahf/vczjk/p63;->$initialValue:Ljava/lang/Object;

    invoke-direct {v1, v3, v5, v6, v4}, Llyiahf/vczjk/o63;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/os5;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/p63;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/rs;->OooOOOO(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_7

    :goto_2
    return-object v0

    :cond_7
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
