.class public final Llyiahf/vczjk/hj8;
.super Landroid/text/style/CharacterStyle;
.source "SourceFile"

# interfaces
.implements Landroid/text/style/UpdateAppearance;


# instance fields
.field public final OooOOO:F

.field public final OooOOO0:Llyiahf/vczjk/fj8;

.field public final OooOOOO:Llyiahf/vczjk/qs5;

.field public final OooOOOo:Llyiahf/vczjk/w62;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fj8;F)V
    .locals 2

    invoke-direct {p0}, Landroid/text/style/CharacterStyle;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hj8;->OooOOO0:Llyiahf/vczjk/fj8;

    iput p2, p0, Llyiahf/vczjk/hj8;->OooOOO:F

    new-instance p1, Llyiahf/vczjk/tq8;

    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/tq8;-><init>(J)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/hj8;->OooOOOO:Llyiahf/vczjk/qs5;

    new-instance p1, Llyiahf/vczjk/gj8;

    invoke-direct {p1, p0}, Llyiahf/vczjk/gj8;-><init>(Llyiahf/vczjk/hj8;)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/hj8;->OooOOOo:Llyiahf/vczjk/w62;

    return-void
.end method


# virtual methods
.method public final updateDrawState(Landroid/text/TextPaint;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/hj8;->OooOOO:F

    invoke-static {p1, v0}, Llyiahf/vczjk/zsa;->oo000o(Landroid/text/TextPaint;F)V

    iget-object v0, p0, Llyiahf/vczjk/hj8;->OooOOOo:Llyiahf/vczjk/w62;

    invoke-virtual {v0}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/graphics/Shader;

    invoke-virtual {p1, v0}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    return-void
.end method
