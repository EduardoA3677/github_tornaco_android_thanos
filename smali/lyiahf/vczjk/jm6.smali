.class public final Llyiahf/vczjk/jm6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/lm6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lm6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    iget-object v0, v0, Llyiahf/vczjk/lm6;->OooOO0O:Llyiahf/vczjk/u32;

    invoke-virtual {v0}, Llyiahf/vczjk/u32;->OooO00o()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    invoke-virtual {v0}, Llyiahf/vczjk/lm6;->OooOO0()I

    move-result v0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    iget-object v0, v0, Llyiahf/vczjk/lm6;->OooOOoo:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    const/4 v1, -0x1

    if-eq v0, v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    iget-object v0, v0, Llyiahf/vczjk/lm6;->OooOOoo:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    iget-object v0, v0, Llyiahf/vczjk/lm6;->OooO0Oo:Llyiahf/vczjk/oO00O0o;

    invoke-virtual {v0}, Llyiahf/vczjk/oO00O0o;->OooO0oO()F

    move-result v0

    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    iget-object v2, v1, Llyiahf/vczjk/lm6;->OooOOo0:Llyiahf/vczjk/f62;

    sget v3, Llyiahf/vczjk/qm6;->OooO00o:F

    invoke-interface {v2, v3}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/lm6;->OooOOO0()I

    move-result v3

    int-to-float v3, v3

    const/high16 v4, 0x40000000    # 2.0f

    div-float/2addr v3, v4

    invoke-static {v2, v3}, Ljava/lang/Math;->min(FF)F

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/lm6;->OooOOO0()I

    move-result v1

    int-to-float v1, v1

    div-float/2addr v2, v1

    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v1

    cmpl-float v0, v0, v1

    if-ltz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    iget-object v0, v0, Llyiahf/vczjk/lm6;->Oooo000:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    iget v0, v0, Llyiahf/vczjk/lm6;->OooO0o0:I

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    iget v0, v0, Llyiahf/vczjk/lm6;->OooO0o0:I

    goto :goto_0

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    invoke-virtual {v0}, Llyiahf/vczjk/lm6;->OooOO0()I

    move-result v0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/jm6;->this$0:Llyiahf/vczjk/lm6;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/lm6;->OooO(I)I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    return-object v0
.end method
