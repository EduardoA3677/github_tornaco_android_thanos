.class public final Llyiahf/vczjk/oh9;
.super Llyiahf/vczjk/cl6;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o:Llyiahf/vczjk/qh9;

.field public final synthetic OooO0o0:Llyiahf/vczjk/vt6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qh9;Llyiahf/vczjk/vt6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oh9;->OooO0o:Llyiahf/vczjk/qh9;

    iput-object p2, p0, Llyiahf/vczjk/oh9;->OooO0o0:Llyiahf/vczjk/vt6;

    return-void
.end method


# virtual methods
.method public final OooOOO(I)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/oh9;->OooO0o:Llyiahf/vczjk/qh9;

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/qh9;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/oh9;->OooO0o0:Llyiahf/vczjk/vt6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vt6;->OooOoOO(I)V

    return-void
.end method

.method public final OooOOOO(Landroid/graphics/Typeface;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/oh9;->OooO0o:Llyiahf/vczjk/qh9;

    iget v1, v0, Llyiahf/vczjk/qh9;->OooO0Oo:I

    invoke-static {p1, v1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    move-result-object p1

    iput-object p1, v0, Llyiahf/vczjk/qh9;->OooOOOo:Landroid/graphics/Typeface;

    const/4 p1, 0x1

    iput-boolean p1, v0, Llyiahf/vczjk/qh9;->OooOOO:Z

    iget-object p1, v0, Llyiahf/vczjk/qh9;->OooOOOo:Landroid/graphics/Typeface;

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/oh9;->OooO0o0:Llyiahf/vczjk/vt6;

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/vt6;->OooOoo0(Landroid/graphics/Typeface;Z)V

    return-void
.end method
