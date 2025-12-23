.class public final Llyiahf/vczjk/o43;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $context:Llyiahf/vczjk/or1;

.field final synthetic $lifecycle:Llyiahf/vczjk/ky4;

.field final synthetic $minActiveState:Llyiahf/vczjk/jy4;

.field final synthetic $this_collectAsStateWithLifecycle:Llyiahf/vczjk/f43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/f43;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o43;->$lifecycle:Llyiahf/vczjk/ky4;

    iput-object p2, p0, Llyiahf/vczjk/o43;->$minActiveState:Llyiahf/vczjk/jy4;

    iput-object p3, p0, Llyiahf/vczjk/o43;->$context:Llyiahf/vczjk/or1;

    iput-object p4, p0, Llyiahf/vczjk/o43;->$this_collectAsStateWithLifecycle:Llyiahf/vczjk/f43;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/o43;

    iget-object v1, p0, Llyiahf/vczjk/o43;->$lifecycle:Llyiahf/vczjk/ky4;

    iget-object v2, p0, Llyiahf/vczjk/o43;->$minActiveState:Llyiahf/vczjk/jy4;

    iget-object v3, p0, Llyiahf/vczjk/o43;->$context:Llyiahf/vczjk/or1;

    iget-object v4, p0, Llyiahf/vczjk/o43;->$this_collectAsStateWithLifecycle:Llyiahf/vczjk/f43;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/o43;-><init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/o43;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/p77;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/o43;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/o43;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/o43;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/o43;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/o43;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/p77;

    iget-object v1, p0, Llyiahf/vczjk/o43;->$lifecycle:Llyiahf/vczjk/ky4;

    iget-object v3, p0, Llyiahf/vczjk/o43;->$minActiveState:Llyiahf/vczjk/jy4;

    new-instance v4, Llyiahf/vczjk/n43;

    iget-object v5, p0, Llyiahf/vczjk/o43;->$context:Llyiahf/vczjk/or1;

    iget-object v6, p0, Llyiahf/vczjk/o43;->$this_collectAsStateWithLifecycle:Llyiahf/vczjk/f43;

    const/4 v7, 0x0

    invoke-direct {v4, v5, v6, p1, v7}, Llyiahf/vczjk/n43;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;Llyiahf/vczjk/p77;Llyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/o43;->label:I

    invoke-static {v1, v3, v4, p0}, Llyiahf/vczjk/qu6;->OooOOo(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
