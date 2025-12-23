.class public final Llyiahf/vczjk/ft;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $it:Ljava/lang/Throwable;

.field final synthetic $listener:Llyiahf/vczjk/ws;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ws;Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ft;->$listener:Llyiahf/vczjk/ws;

    iput-object p2, p0, Llyiahf/vczjk/ft;->$it:Ljava/lang/Throwable;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/ft;

    iget-object v0, p0, Llyiahf/vczjk/ft;->$listener:Llyiahf/vczjk/ws;

    iget-object v1, p0, Llyiahf/vczjk/ft;->$it:Ljava/lang/Throwable;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/ft;-><init>(Llyiahf/vczjk/ws;Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ft;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ft;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ft;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/ft;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ft;->$listener:Llyiahf/vczjk/ws;

    iget-object v0, p0, Llyiahf/vczjk/ft;->$it:Ljava/lang/Throwable;

    invoke-static {v0}, Llyiahf/vczjk/cp7;->Oooo0o(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/us;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/us;->OooO00o(Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
