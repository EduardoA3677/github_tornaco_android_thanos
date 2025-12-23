.class public final Llyiahf/vczjk/qp1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $imeOptions:Llyiahf/vczjk/wv3;

.field final synthetic $manager:Llyiahf/vczjk/mk9;

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $textInputService:Llyiahf/vczjk/tl9;

.field final synthetic $writeable$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/p29;Llyiahf/vczjk/tl9;Llyiahf/vczjk/mk9;Llyiahf/vczjk/wv3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qp1;->$state:Llyiahf/vczjk/lx4;

    iput-object p2, p0, Llyiahf/vczjk/qp1;->$writeable$delegate:Llyiahf/vczjk/p29;

    iput-object p3, p0, Llyiahf/vczjk/qp1;->$textInputService:Llyiahf/vczjk/tl9;

    iput-object p4, p0, Llyiahf/vczjk/qp1;->$manager:Llyiahf/vczjk/mk9;

    iput-object p5, p0, Llyiahf/vczjk/qp1;->$imeOptions:Llyiahf/vczjk/wv3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/qp1;

    iget-object v1, p0, Llyiahf/vczjk/qp1;->$state:Llyiahf/vczjk/lx4;

    iget-object v2, p0, Llyiahf/vczjk/qp1;->$writeable$delegate:Llyiahf/vczjk/p29;

    iget-object v3, p0, Llyiahf/vczjk/qp1;->$textInputService:Llyiahf/vczjk/tl9;

    iget-object v4, p0, Llyiahf/vczjk/qp1;->$manager:Llyiahf/vczjk/mk9;

    iget-object v5, p0, Llyiahf/vczjk/qp1;->$imeOptions:Llyiahf/vczjk/wv3;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/qp1;-><init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/p29;Llyiahf/vczjk/tl9;Llyiahf/vczjk/mk9;Llyiahf/vczjk/wv3;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qp1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qp1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/qp1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/qp1;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    new-instance p1, Llyiahf/vczjk/op1;

    iget-object v1, p0, Llyiahf/vczjk/qp1;->$writeable$delegate:Llyiahf/vczjk/p29;

    invoke-direct {p1, v1}, Llyiahf/vczjk/op1;-><init>(Llyiahf/vczjk/p29;)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0o(Llyiahf/vczjk/le3;)Llyiahf/vczjk/s48;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/pp1;

    iget-object v4, p0, Llyiahf/vczjk/qp1;->$state:Llyiahf/vczjk/lx4;

    iget-object v5, p0, Llyiahf/vczjk/qp1;->$textInputService:Llyiahf/vczjk/tl9;

    iget-object v6, p0, Llyiahf/vczjk/qp1;->$manager:Llyiahf/vczjk/mk9;

    iget-object v7, p0, Llyiahf/vczjk/qp1;->$imeOptions:Llyiahf/vczjk/wv3;

    const/4 v8, 0x0

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/pp1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/qp1;->label:I

    invoke-virtual {p1, v3, p0}, Llyiahf/vczjk/o00O0000;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/qp1;->$state:Llyiahf/vczjk/lx4;

    invoke-static {p1}, Llyiahf/vczjk/sb;->OooOOOo(Llyiahf/vczjk/lx4;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/qp1;->$state:Llyiahf/vczjk/lx4;

    invoke-static {v0}, Llyiahf/vczjk/sb;->OooOOOo(Llyiahf/vczjk/lx4;)V

    throw p1
.end method
