.class public final Llyiahf/vczjk/p20;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $lifecycle:Llyiahf/vczjk/ky4;

.field final synthetic $props:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $vm:Llyiahf/vczjk/i40;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i40;Llyiahf/vczjk/ky4;Ljava/util/List;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/p20;->$vm:Llyiahf/vczjk/i40;

    iput-object p2, p0, Llyiahf/vczjk/p20;->$lifecycle:Llyiahf/vczjk/ky4;

    iput-object p3, p0, Llyiahf/vczjk/p20;->$props:Ljava/util/List;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/p20;

    iget-object v0, p0, Llyiahf/vczjk/p20;->$vm:Llyiahf/vczjk/i40;

    iget-object v1, p0, Llyiahf/vczjk/p20;->$lifecycle:Llyiahf/vczjk/ky4;

    iget-object v2, p0, Llyiahf/vczjk/p20;->$props:Ljava/util/List;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/p20;-><init>(Llyiahf/vczjk/i40;Llyiahf/vczjk/ky4;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/p20;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p20;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/p20;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/p20;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/p20;->$vm:Llyiahf/vczjk/i40;

    iget-object v0, p0, Llyiahf/vczjk/p20;->$lifecycle:Llyiahf/vczjk/ky4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fy4;->OooO0o0(Llyiahf/vczjk/ky4;)V

    iget-object p1, p0, Llyiahf/vczjk/p20;->$vm:Llyiahf/vczjk/i40;

    iget-object v0, p0, Llyiahf/vczjk/p20;->$props:Ljava/util/List;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "props"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/t30;

    const/4 v3, 0x0

    invoke-direct {v2, v0, p1, v3}, Llyiahf/vczjk/t30;-><init>(Ljava/util/List;Llyiahf/vczjk/i40;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v1, v3, v3, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
