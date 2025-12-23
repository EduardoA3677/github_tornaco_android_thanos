.class public final Llyiahf/vczjk/up0;
.super Llyiahf/vczjk/vt6;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Landroid/graphics/Typeface;

.field public final OooO0OO:Llyiahf/vczjk/tp0;

.field public OooO0Oo:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tp0;Landroid/graphics/Typeface;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/up0;->OooO0O0:Landroid/graphics/Typeface;

    iput-object p1, p0, Llyiahf/vczjk/up0;->OooO0OO:Llyiahf/vczjk/tp0;

    return-void
.end method


# virtual methods
.method public final OooOoOO(I)V
    .locals 1

    iget-boolean p1, p0, Llyiahf/vczjk/up0;->OooO0Oo:Z

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/up0;->OooO0OO:Llyiahf/vczjk/tp0;

    iget-object v0, p0, Llyiahf/vczjk/up0;->OooO0O0:Landroid/graphics/Typeface;

    invoke-interface {p1, v0}, Llyiahf/vczjk/tp0;->OooOo(Landroid/graphics/Typeface;)V

    :cond_0
    return-void
.end method

.method public final OooOoo0(Landroid/graphics/Typeface;Z)V
    .locals 0

    iget-boolean p2, p0, Llyiahf/vczjk/up0;->OooO0Oo:Z

    if-nez p2, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/up0;->OooO0OO:Llyiahf/vczjk/tp0;

    invoke-interface {p2, p1}, Llyiahf/vczjk/tp0;->OooOo(Landroid/graphics/Typeface;)V

    :cond_0
    return-void
.end method
