.class public final Llyiahf/vczjk/q9;
.super Llyiahf/vczjk/c20;
.source "SourceFile"


# instance fields
.field public OooO:Z

.field public final OooO00o:Llyiahf/vczjk/oO0OOo0o;

.field public final OooO0O0:Llyiahf/vczjk/ue8;

.field public final OooO0OO:Llyiahf/vczjk/xa;

.field public final OooO0Oo:Llyiahf/vczjk/zj7;

.field public final OooO0o:Landroid/graphics/Rect;

.field public final OooO0o0:Ljava/lang/String;

.field public final OooO0oO:Landroid/view/autofill/AutofillId;

.field public final OooO0oo:Llyiahf/vczjk/pr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oO0OOo0o;Llyiahf/vczjk/ue8;Llyiahf/vczjk/xa;Llyiahf/vczjk/zj7;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q9;->OooO00o:Llyiahf/vczjk/oO0OOo0o;

    iput-object p2, p0, Llyiahf/vczjk/q9;->OooO0O0:Llyiahf/vczjk/ue8;

    iput-object p3, p0, Llyiahf/vczjk/q9;->OooO0OO:Llyiahf/vczjk/xa;

    iput-object p4, p0, Llyiahf/vczjk/q9;->OooO0Oo:Llyiahf/vczjk/zj7;

    iput-object p5, p0, Llyiahf/vczjk/q9;->OooO0o0:Ljava/lang/String;

    new-instance p1, Landroid/graphics/Rect;

    invoke-direct {p1}, Landroid/graphics/Rect;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q9;->OooO0o:Landroid/graphics/Rect;

    invoke-static {p3}, Llyiahf/vczjk/o00O0OO;->OooOoO(Llyiahf/vczjk/xa;)V

    invoke-static {p3}, Llyiahf/vczjk/ll6;->OooO0o(Landroid/view/View;)Llyiahf/vczjk/sw7;

    move-result-object p1

    if-eqz p1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/cr;->OooO0o(Ljava/lang/Object;)Landroid/view/autofill/AutofillId;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_1

    iput-object p1, p0, Llyiahf/vczjk/q9;->OooO0oO:Landroid/view/autofill/AutofillId;

    new-instance p1, Llyiahf/vczjk/pr5;

    invoke-direct {p1}, Llyiahf/vczjk/pr5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q9;->OooO0oo:Llyiahf/vczjk/pr5;

    return-void

    :cond_1
    const-string p1, "Required value was null."

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object p1

    throw p1
.end method
