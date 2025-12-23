.class public final Llyiahf/vczjk/yn1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $enabled:Z

.field final synthetic $label:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $leadingIcon:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $onClick:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ro1;Llyiahf/vczjk/le3;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iput-object p1, p0, Llyiahf/vczjk/yn1;->$label:Llyiahf/vczjk/ze3;

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/yn1;->$enabled:Z

    iput-object v0, p0, Llyiahf/vczjk/yn1;->$modifier:Llyiahf/vczjk/kl5;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/yn1;->$leadingIcon:Llyiahf/vczjk/bf3;

    iput-object p2, p0, Llyiahf/vczjk/yn1;->$onClick:Llyiahf/vczjk/le3;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/tn1;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p1

    and-int/lit8 p3, p1, 0x6

    if-nez p3, :cond_1

    move-object p3, p2

    check-cast p3, Llyiahf/vczjk/zf1;

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_0

    const/4 p3, 0x4

    goto :goto_0

    :cond_0
    const/4 p3, 0x2

    :goto_0
    or-int/2addr p1, p3

    :cond_1
    and-int/lit8 p3, p1, 0x13

    const/16 v0, 0x12

    const/4 v1, 0x0

    if-eq p3, v0, :cond_2

    const/4 p3, 0x1

    goto :goto_1

    :cond_2
    move p3, v1

    :goto_1
    and-int/lit8 v0, p1, 0x1

    move-object v6, p2

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6, v0, p3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_4

    iget-object p2, p0, Llyiahf/vczjk/yn1;->$label:Llyiahf/vczjk/ze3;

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p3

    invoke-interface {p2, v6, p3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    move-object v0, p2

    check-cast v0, Ljava/lang/String;

    invoke-static {v0}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result p2

    if-eqz p2, :cond_3

    const-string p2, "Label must not be blank"

    invoke-static {p2}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :cond_3
    iget-boolean v1, p0, Llyiahf/vczjk/yn1;->$enabled:Z

    iget-object v3, p0, Llyiahf/vczjk/yn1;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v4, p0, Llyiahf/vczjk/yn1;->$leadingIcon:Llyiahf/vczjk/bf3;

    iget-object v5, p0, Llyiahf/vczjk/yn1;->$onClick:Llyiahf/vczjk/le3;

    shl-int/lit8 p1, p1, 0x6

    and-int/lit16 v7, p1, 0x380

    const/4 v8, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/mo1;->OooO0O0(Ljava/lang/String;ZLlyiahf/vczjk/tn1;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    goto :goto_2

    :cond_4
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
