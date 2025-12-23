.class public final Llyiahf/vczjk/poa;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooOo0O:Ljava/util/WeakHashMap;


# instance fields
.field public final OooO:Llyiahf/vczjk/xh;

.field public final OooO00o:Llyiahf/vczjk/xh;

.field public final OooO0O0:Llyiahf/vczjk/xh;

.field public final OooO0OO:Llyiahf/vczjk/xh;

.field public final OooO0Oo:Llyiahf/vczjk/xh;

.field public final OooO0o:Llyiahf/vczjk/xh;

.field public final OooO0o0:Llyiahf/vczjk/xh;

.field public final OooO0oO:Llyiahf/vczjk/xh;

.field public final OooO0oo:Llyiahf/vczjk/xh;

.field public final OooOO0:Llyiahf/vczjk/kca;

.field public final OooOO0O:Llyiahf/vczjk/x8a;

.field public final OooOO0o:Llyiahf/vczjk/kca;

.field public final OooOOO:Llyiahf/vczjk/kca;

.field public final OooOOO0:Llyiahf/vczjk/kca;

.field public final OooOOOO:Llyiahf/vczjk/kca;

.field public final OooOOOo:Llyiahf/vczjk/kca;

.field public final OooOOo:Llyiahf/vczjk/kca;

.field public final OooOOo0:Llyiahf/vczjk/kca;

.field public final OooOOoo:Z

.field public final OooOo0:Llyiahf/vczjk/a14;

.field public OooOo00:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Ljava/util/WeakHashMap;

    invoke-direct {v0}, Ljava/util/WeakHashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/poa;->OooOo0O:Ljava/util/WeakHashMap;

    return-void
.end method

.method public constructor <init>(Landroid/view/View;)V
    .locals 16

    move-object/from16 v0, p0

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    const-string v1, "captionBar"

    const/4 v2, 0x4

    invoke-static {v2, v1}, Llyiahf/vczjk/qp3;->OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooO00o:Llyiahf/vczjk/xh;

    const/16 v1, 0x80

    const-string v3, "displayCutout"

    invoke-static {v1, v3}, Llyiahf/vczjk/qp3;->OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooO0O0:Llyiahf/vczjk/xh;

    const-string v3, "ime"

    const/16 v4, 0x8

    invoke-static {v4, v3}, Llyiahf/vczjk/qp3;->OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;

    move-result-object v3

    iput-object v3, v0, Llyiahf/vczjk/poa;->OooO0OO:Llyiahf/vczjk/xh;

    const/16 v5, 0x20

    const-string v6, "mandatorySystemGestures"

    invoke-static {v5, v6}, Llyiahf/vczjk/qp3;->OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;

    move-result-object v5

    iput-object v5, v0, Llyiahf/vczjk/poa;->OooO0Oo:Llyiahf/vczjk/xh;

    const-string v6, "navigationBars"

    const/4 v7, 0x2

    invoke-static {v7, v6}, Llyiahf/vczjk/qp3;->OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;

    move-result-object v6

    iput-object v6, v0, Llyiahf/vczjk/poa;->OooO0o0:Llyiahf/vczjk/xh;

    const-string v6, "statusBars"

    const/4 v8, 0x1

    invoke-static {v8, v6}, Llyiahf/vczjk/qp3;->OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;

    move-result-object v6

    iput-object v6, v0, Llyiahf/vczjk/poa;->OooO0o:Llyiahf/vczjk/xh;

    const-string v6, "systemBars"

    const/16 v9, 0x207

    invoke-static {v9, v6}, Llyiahf/vczjk/qp3;->OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;

    move-result-object v6

    iput-object v6, v0, Llyiahf/vczjk/poa;->OooO0oO:Llyiahf/vczjk/xh;

    const/16 v10, 0x10

    const-string v11, "systemGestures"

    invoke-static {v10, v11}, Llyiahf/vczjk/qp3;->OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;

    move-result-object v10

    iput-object v10, v0, Llyiahf/vczjk/poa;->OooO0oo:Llyiahf/vczjk/xh;

    const-string v11, "tappableElement"

    const/16 v12, 0x40

    invoke-static {v12, v11}, Llyiahf/vczjk/qp3;->OooOo00(ILjava/lang/String;)Llyiahf/vczjk/xh;

    move-result-object v11

    iput-object v11, v0, Llyiahf/vczjk/poa;->OooO:Llyiahf/vczjk/xh;

    new-instance v13, Llyiahf/vczjk/kca;

    new-instance v14, Llyiahf/vczjk/e14;

    const/4 v15, 0x0

    invoke-direct {v14, v15, v15, v15, v15}, Llyiahf/vczjk/e14;-><init>(IIII)V

    const-string v15, "waterfall"

    invoke-direct {v13, v14, v15}, Llyiahf/vczjk/kca;-><init>(Llyiahf/vczjk/e14;Ljava/lang/String;)V

    iput-object v13, v0, Llyiahf/vczjk/poa;->OooOO0:Llyiahf/vczjk/kca;

    new-instance v14, Llyiahf/vczjk/x8a;

    invoke-direct {v14, v6, v3}, Llyiahf/vczjk/x8a;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kna;)V

    new-instance v3, Llyiahf/vczjk/x8a;

    invoke-direct {v3, v14, v1}, Llyiahf/vczjk/x8a;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kna;)V

    iput-object v3, v0, Llyiahf/vczjk/poa;->OooOO0O:Llyiahf/vczjk/x8a;

    new-instance v1, Llyiahf/vczjk/x8a;

    invoke-direct {v1, v11, v5}, Llyiahf/vczjk/x8a;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kna;)V

    new-instance v3, Llyiahf/vczjk/x8a;

    invoke-direct {v3, v1, v10}, Llyiahf/vczjk/x8a;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kna;)V

    new-instance v1, Llyiahf/vczjk/x8a;

    invoke-direct {v1, v3, v13}, Llyiahf/vczjk/x8a;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kna;)V

    const-string v1, "captionBarIgnoringVisibility"

    invoke-static {v2, v1}, Llyiahf/vczjk/qp3;->OooOo0(ILjava/lang/String;)Llyiahf/vczjk/kca;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooOO0o:Llyiahf/vczjk/kca;

    const-string v1, "navigationBarsIgnoringVisibility"

    invoke-static {v7, v1}, Llyiahf/vczjk/qp3;->OooOo0(ILjava/lang/String;)Llyiahf/vczjk/kca;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooOOO0:Llyiahf/vczjk/kca;

    const-string v1, "statusBarsIgnoringVisibility"

    invoke-static {v8, v1}, Llyiahf/vczjk/qp3;->OooOo0(ILjava/lang/String;)Llyiahf/vczjk/kca;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooOOO:Llyiahf/vczjk/kca;

    const-string v1, "systemBarsIgnoringVisibility"

    invoke-static {v9, v1}, Llyiahf/vczjk/qp3;->OooOo0(ILjava/lang/String;)Llyiahf/vczjk/kca;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooOOOO:Llyiahf/vczjk/kca;

    const-string v1, "tappableElementIgnoringVisibility"

    invoke-static {v12, v1}, Llyiahf/vczjk/qp3;->OooOo0(ILjava/lang/String;)Llyiahf/vczjk/kca;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooOOOo:Llyiahf/vczjk/kca;

    const-string v1, "imeAnimationTarget"

    invoke-static {v4, v1}, Llyiahf/vczjk/qp3;->OooOo0(ILjava/lang/String;)Llyiahf/vczjk/kca;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooOOo0:Llyiahf/vczjk/kca;

    const-string v1, "imeAnimationSource"

    invoke-static {v4, v1}, Llyiahf/vczjk/qp3;->OooOo0(ILjava/lang/String;)Llyiahf/vczjk/kca;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooOOo:Llyiahf/vczjk/kca;

    invoke-virtual/range {p1 .. p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v1

    instance-of v2, v1, Landroid/view/View;

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    check-cast v1, Landroid/view/View;

    goto :goto_0

    :cond_0
    move-object v1, v3

    :goto_0
    if-eqz v1, :cond_1

    sget v2, Landroidx/compose/ui/R$id;->consume_window_insets_tag:I

    invoke-virtual {v1, v2}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v1

    goto :goto_1

    :cond_1
    move-object v1, v3

    :goto_1
    instance-of v2, v1, Ljava/lang/Boolean;

    if-eqz v2, :cond_2

    move-object v3, v1

    check-cast v3, Ljava/lang/Boolean;

    :cond_2
    if-eqz v3, :cond_3

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v8

    :cond_3
    iput-boolean v8, v0, Llyiahf/vczjk/poa;->OooOOoo:Z

    new-instance v1, Llyiahf/vczjk/a14;

    invoke-direct {v1, v0}, Llyiahf/vczjk/a14;-><init>(Llyiahf/vczjk/poa;)V

    iput-object v1, v0, Llyiahf/vczjk/poa;->OooOo0:Llyiahf/vczjk/a14;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/poa;Llyiahf/vczjk/ioa;)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooO00o:Llyiahf/vczjk/xh;

    const/4 v1, 0x0

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/xh;->OooO0o(Llyiahf/vczjk/ioa;I)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooO0OO:Llyiahf/vczjk/xh;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/xh;->OooO0o(Llyiahf/vczjk/ioa;I)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooO0O0:Llyiahf/vczjk/xh;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/xh;->OooO0o(Llyiahf/vczjk/ioa;I)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooO0o0:Llyiahf/vczjk/xh;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/xh;->OooO0o(Llyiahf/vczjk/ioa;I)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooO0o:Llyiahf/vczjk/xh;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/xh;->OooO0o(Llyiahf/vczjk/ioa;I)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooO0oO:Llyiahf/vczjk/xh;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/xh;->OooO0o(Llyiahf/vczjk/ioa;I)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooO0oo:Llyiahf/vczjk/xh;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/xh;->OooO0o(Llyiahf/vczjk/ioa;I)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooO:Llyiahf/vczjk/xh;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/xh;->OooO0o(Llyiahf/vczjk/ioa;I)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooO0Oo:Llyiahf/vczjk/xh;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/xh;->OooO0o(Llyiahf/vczjk/ioa;I)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooOO0o:Llyiahf/vczjk/kca;

    iget-object v2, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/4 v3, 0x4

    invoke-virtual {v2, v3}, Llyiahf/vczjk/foa;->OooO0oo(I)Llyiahf/vczjk/x04;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooOOO0:Llyiahf/vczjk/kca;

    iget-object v2, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/4 v3, 0x2

    invoke-virtual {v2, v3}, Llyiahf/vczjk/foa;->OooO0oo(I)Llyiahf/vczjk/x04;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooOOO:Llyiahf/vczjk/kca;

    iget-object v2, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/4 v3, 0x1

    invoke-virtual {v2, v3}, Llyiahf/vczjk/foa;->OooO0oo(I)Llyiahf/vczjk/x04;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooOOOO:Llyiahf/vczjk/kca;

    iget-object v2, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v4, 0x207

    invoke-virtual {v2, v4}, Llyiahf/vczjk/foa;->OooO0oo(I)Llyiahf/vczjk/x04;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    iget-object v0, p0, Llyiahf/vczjk/poa;->OooOOOo:Llyiahf/vczjk/kca;

    iget-object v2, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v4, 0x40

    invoke-virtual {v2, v4}, Llyiahf/vczjk/foa;->OooO0oo(I)Llyiahf/vczjk/x04;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    iget-object p1, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {p1}, Llyiahf/vczjk/foa;->OooO0o()Llyiahf/vczjk/lc2;

    move-result-object p1

    if-eqz p1, :cond_1

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x1e

    if-lt v0, v2, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/lc2;->OooO00o:Landroid/view/DisplayCutout;

    invoke-static {p1}, Llyiahf/vczjk/o0O0o00O;->OooO0oO(Landroid/view/DisplayCutout;)Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/x04;->OooO0Oo(Landroid/graphics/Insets;)Llyiahf/vczjk/x04;

    move-result-object p1

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/x04;->OooO0o0:Llyiahf/vczjk/x04;

    :goto_0
    iget-object p0, p0, Llyiahf/vczjk/poa;->OooOO0:Llyiahf/vczjk/kca;

    invoke-static {p1}, Llyiahf/vczjk/tn6;->OooOo00(Llyiahf/vczjk/x04;)Llyiahf/vczjk/e14;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/kca;->OooO0o(Llyiahf/vczjk/e14;)V

    :cond_1
    sget-object p0, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter p0

    :try_start_0
    sget-object p1, Llyiahf/vczjk/vv8;->OooO:Llyiahf/vczjk/li3;

    iget-object p1, p1, Llyiahf/vczjk/ps5;->OooO0oo:Llyiahf/vczjk/ks5;

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/a88;->OooO0OO()Z

    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-ne p1, v3, :cond_2

    move v1, v3

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_2
    :goto_1
    monitor-exit p0

    if-eqz v1, :cond_3

    invoke-static {}, Llyiahf/vczjk/vv8;->OooO00o()V

    :cond_3
    return-void

    :goto_2
    monitor-exit p0

    throw p1
.end method
