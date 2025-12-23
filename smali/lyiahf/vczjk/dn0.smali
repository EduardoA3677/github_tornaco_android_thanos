.class public final Llyiahf/vczjk/dn0;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jn0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jn0;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jn0;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dn0;->this$0:Llyiahf/vczjk/jn0;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/dn0;

    iget-object v1, p0, Llyiahf/vczjk/dn0;->this$0:Llyiahf/vczjk/jn0;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/dn0;-><init>(Llyiahf/vczjk/jn0;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/dn0;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/dn0;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dn0;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/dn0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/dn0;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/dn0;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    new-instance v1, Llyiahf/vczjk/fl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    const/high16 v3, -0x80000000

    iput v3, v1, Llyiahf/vczjk/fl7;->element:I

    iget-object v3, p0, Llyiahf/vczjk/dn0;->this$0:Llyiahf/vczjk/jn0;

    iget-object v3, v3, Llyiahf/vczjk/jn0;->OooO0OO:Llyiahf/vczjk/a99;

    new-instance v4, Llyiahf/vczjk/an0;

    const/4 v5, 0x2

    const/4 v6, 0x0

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v5, Llyiahf/vczjk/a63;

    invoke-direct {v5, v3, v4}, Llyiahf/vczjk/a63;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V

    new-instance v3, Llyiahf/vczjk/cn0;

    invoke-direct {v3, p1, v1}, Llyiahf/vczjk/cn0;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/fl7;)V

    iput v2, p0, Llyiahf/vczjk/dn0;->label:I

    invoke-virtual {v5, v3, p0}, Llyiahf/vczjk/a63;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
