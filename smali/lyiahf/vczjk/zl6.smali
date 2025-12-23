.class public final Llyiahf/vczjk/zl6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/km6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/km6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zl6;->this$0:Llyiahf/vczjk/km6;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zl6;->this$0:Llyiahf/vczjk/km6;

    invoke-virtual {v0}, Llyiahf/vczjk/km6;->OooO0o()Llyiahf/vczjk/gv4;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/zl6;->this$0:Llyiahf/vczjk/km6;

    check-cast v0, Llyiahf/vczjk/tv4;

    iget v2, v0, Llyiahf/vczjk/tv4;->OooOOOo:I

    neg-int v2, v2

    int-to-float v2, v2

    iget-object v1, v1, Llyiahf/vczjk/km6;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    iget v0, v0, Llyiahf/vczjk/tv4;->OooOOo0:I

    add-int/2addr v1, v0

    int-to-float v0, v1

    div-float/2addr v2, v0

    const/high16 v0, -0x41000000    # -0.5f

    const/high16 v1, 0x3f000000    # 0.5f

    invoke-static {v2, v0, v1}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0
.end method
