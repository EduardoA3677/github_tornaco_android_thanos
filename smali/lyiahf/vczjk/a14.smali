.class public final Llyiahf/vczjk/a14;
.super Llyiahf/vczjk/i11;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;
.implements Llyiahf/vczjk/u96;
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/poa;

.field public OooOOOo:Z

.field public OooOOo:Llyiahf/vczjk/ioa;

.field public OooOOo0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/poa;)V
    .locals 1

    iget-boolean v0, p1, Llyiahf/vczjk/poa;->OooOOoo:Z

    xor-int/lit8 v0, v0, 0x1

    invoke-direct {p0, v0}, Llyiahf/vczjk/i11;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/a14;->OooOOOO:Llyiahf/vczjk/poa;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/sna;)V
    .locals 5

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/a14;->OooOOOo:Z

    iput-boolean v0, p0, Llyiahf/vczjk/a14;->OooOOo0:Z

    iget-object v0, p0, Llyiahf/vczjk/a14;->OooOOo:Llyiahf/vczjk/ioa;

    iget-object p1, p1, Llyiahf/vczjk/sna;->OooO00o:Llyiahf/vczjk/rna;

    invoke-virtual {p1}, Llyiahf/vczjk/rna;->OooO0O0()J

    move-result-wide v1

    const-wide/16 v3, 0x0

    cmp-long p1, v1, v3

    if-eqz p1, :cond_0

    if-eqz v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/a14;->OooOOOO:Llyiahf/vczjk/poa;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v2, 0x8

    invoke-virtual {v1, v2}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object v3

    iget-object v4, p1, Llyiahf/vczjk/poa;->OooOOo:Llyiahf/vczjk/kca;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object v1

    iget-object v2, p1, Llyiahf/vczjk/poa;->OooOOo0:Llyiahf/vczjk/kca;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/poa;->OooO00o(Llyiahf/vczjk/poa;Llyiahf/vczjk/ioa;)V

    :cond_0
    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/a14;->OooOOo:Llyiahf/vczjk/ioa;

    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/ioa;Ljava/util/List;)Llyiahf/vczjk/ioa;
    .locals 0

    iget-object p2, p0, Llyiahf/vczjk/a14;->OooOOOO:Llyiahf/vczjk/poa;

    invoke-static {p2, p1}, Llyiahf/vczjk/poa;->OooO00o(Llyiahf/vczjk/poa;Llyiahf/vczjk/ioa;)V

    iget-boolean p2, p2, Llyiahf/vczjk/poa;->OooOOoo:Z

    if-eqz p2, :cond_0

    sget-object p1, Llyiahf/vczjk/ioa;->OooO0O0:Llyiahf/vczjk/ioa;

    :cond_0
    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/sna;)V
    .locals 0

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/a14;->OooOOOo:Z

    iput-boolean p1, p0, Llyiahf/vczjk/a14;->OooOOo0:Z

    return-void
.end method

.method public final OooO0oO(Llyiahf/vczjk/sna;Llyiahf/vczjk/bp8;)Llyiahf/vczjk/bp8;
    .locals 0

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/a14;->OooOOOo:Z

    return-object p2
.end method

.method public final Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;
    .locals 5

    iput-object p2, p0, Llyiahf/vczjk/a14;->OooOOo:Llyiahf/vczjk/ioa;

    iget-object v0, p0, Llyiahf/vczjk/a14;->OooOOOO:Llyiahf/vczjk/poa;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p2, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v2, 0x8

    invoke-virtual {v1, v2}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object v3

    iget-object v4, v0, Llyiahf/vczjk/poa;->OooOOo0:Llyiahf/vczjk/kca;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    iget-boolean v3, p0, Llyiahf/vczjk/a14;->OooOOOo:Z

    if-eqz v3, :cond_0

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x1e

    if-ne v1, v2, :cond_1

    invoke-virtual {p1, p0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    goto :goto_0

    :cond_0
    iget-boolean p1, p0, Llyiahf/vczjk/a14;->OooOOo0:Z

    if-nez p1, :cond_1

    invoke-virtual {v1, v2}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object p1

    iget-object v1, v0, Llyiahf/vczjk/poa;->OooOOo:Llyiahf/vczjk/kca;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/poa;->OooO00o(Llyiahf/vczjk/poa;Llyiahf/vczjk/ioa;)V

    :cond_1
    :goto_0
    iget-boolean p1, v0, Llyiahf/vczjk/poa;->OooOOoo:Z

    if-eqz p1, :cond_2

    sget-object p1, Llyiahf/vczjk/ioa;->OooO0O0:Llyiahf/vczjk/ioa;

    return-object p1

    :cond_2
    return-object p2
.end method

.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 0

    invoke-virtual {p1}, Landroid/view/View;->requestApplyInsets()V

    return-void
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 0

    return-void
.end method

.method public final run()V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/a14;->OooOOOo:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/a14;->OooOOOo:Z

    iput-boolean v0, p0, Llyiahf/vczjk/a14;->OooOOo0:Z

    iget-object v0, p0, Llyiahf/vczjk/a14;->OooOOo:Llyiahf/vczjk/ioa;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/a14;->OooOOOO:Llyiahf/vczjk/poa;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v3, 0x8

    invoke-virtual {v2, v3}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object v2

    iget-object v3, v1, Llyiahf/vczjk/poa;->OooOOo:Llyiahf/vczjk/kca;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    invoke-static {v1, v0}, Llyiahf/vczjk/poa;->OooO00o(Llyiahf/vczjk/poa;Llyiahf/vczjk/ioa;)V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/a14;->OooOOo:Llyiahf/vczjk/ioa;

    :cond_0
    return-void
.end method
