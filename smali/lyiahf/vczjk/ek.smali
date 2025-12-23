.class public final Llyiahf/vczjk/ek;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $shape:Llyiahf/vczjk/ir1;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/fk;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/ir1;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ek;->this$0:Llyiahf/vczjk/fk;

    iput-object p2, p0, Llyiahf/vczjk/ek;->$shape:Llyiahf/vczjk/ir1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ek;

    iget-object v1, p0, Llyiahf/vczjk/ek;->this$0:Llyiahf/vczjk/fk;

    iget-object v2, p0, Llyiahf/vczjk/ek;->$shape:Llyiahf/vczjk/ir1;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/ek;-><init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/ir1;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ek;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ek;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ek;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ek;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/ek;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ek;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    new-instance v0, Llyiahf/vczjk/ak;

    iget-object v1, p0, Llyiahf/vczjk/ek;->this$0:Llyiahf/vczjk/fk;

    iget-object v2, p0, Llyiahf/vczjk/ek;->$shape:Llyiahf/vczjk/ir1;

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/ak;-><init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/ir1;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    invoke-static {p1, v3, v3, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v0, Llyiahf/vczjk/bk;

    iget-object v2, p0, Llyiahf/vczjk/ek;->this$0:Llyiahf/vczjk/fk;

    iget-object v4, p0, Llyiahf/vczjk/ek;->$shape:Llyiahf/vczjk/ir1;

    invoke-direct {v0, v2, v4, v3}, Llyiahf/vczjk/bk;-><init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/ir1;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v0, Llyiahf/vczjk/ck;

    iget-object v2, p0, Llyiahf/vczjk/ek;->this$0:Llyiahf/vczjk/fk;

    iget-object v4, p0, Llyiahf/vczjk/ek;->$shape:Llyiahf/vczjk/ir1;

    invoke-direct {v0, v2, v4, v3}, Llyiahf/vczjk/ck;-><init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/ir1;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v0, Llyiahf/vczjk/dk;

    iget-object v2, p0, Llyiahf/vczjk/ek;->this$0:Llyiahf/vczjk/fk;

    iget-object v4, p0, Llyiahf/vczjk/ek;->$shape:Llyiahf/vczjk/ir1;

    invoke-direct {v0, v2, v4, v3}, Llyiahf/vczjk/dk;-><init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/ir1;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
