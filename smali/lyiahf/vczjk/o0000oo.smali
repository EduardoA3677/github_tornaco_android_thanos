.class public final Llyiahf/vczjk/o0000oo;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/o0000O0O;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o0000O0O;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o0000oo;->this$0:Llyiahf/vczjk/o0000O0O;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/o0000oo;

    iget-object v0, p0, Llyiahf/vczjk/o0000oo;->this$0:Llyiahf/vczjk/o0000O0O;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/o0000oo;-><init>(Llyiahf/vczjk/o0000O0O;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/o0000oo;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/o0000oo;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/o0000oo;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/o0000oo;->label:I

    if-nez v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/o0000oo;->this$0:Llyiahf/vczjk/o0000O0O;

    iget-object v0, p1, Llyiahf/vczjk/o0000O0O;->Oooo0o:Llyiahf/vczjk/wo3;

    if-eqz v0, :cond_1

    new-instance v1, Llyiahf/vczjk/xo3;

    invoke-direct {v1, v0}, Llyiahf/vczjk/xo3;-><init>(Llyiahf/vczjk/wo3;)V

    iget-object v0, p1, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    const/4 v2, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/o000000O;

    invoke-direct {v4, v0, v1, v2}, Llyiahf/vczjk/o000000O;-><init>(Llyiahf/vczjk/rr5;Llyiahf/vczjk/xo3;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {v3, v2, v2, v4, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_0
    iput-object v2, p1, Llyiahf/vczjk/o0000O0O;->Oooo0o:Llyiahf/vczjk/wo3;

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
