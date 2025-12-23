.class public final Llyiahf/vczjk/pf1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $this_materializeImpl:Llyiahf/vczjk/rf1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rf1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pf1;->$this_materializeImpl:Llyiahf/vczjk/rf1;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/il5;

    instance-of v0, p2, Llyiahf/vczjk/of1;

    if-eqz v0, :cond_0

    check-cast p2, Llyiahf/vczjk/of1;

    iget-object p2, p2, Llyiahf/vczjk/of1;->OooOOO0:Llyiahf/vczjk/bf3;

    const/4 v0, 0x3

    invoke-static {v0, p2}, Llyiahf/vczjk/l4a;->OooOO0(ILjava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v1, p0, Llyiahf/vczjk/pf1;->$this_materializeImpl:Llyiahf/vczjk/rf1;

    const/4 v2, 0x0

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-interface {p2, v0, v1, v2}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/kl5;

    iget-object v0, p0, Llyiahf/vczjk/pf1;->$this_materializeImpl:Llyiahf/vczjk/rf1;

    invoke-static {v0, p2}, Llyiahf/vczjk/ng0;->Oooo0oo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    :cond_0
    invoke-interface {p1, p2}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    return-object p1
.end method
