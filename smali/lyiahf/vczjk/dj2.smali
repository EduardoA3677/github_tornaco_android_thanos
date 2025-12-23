.class public final Llyiahf/vczjk/dj2;
.super Llyiahf/vczjk/n62;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOo0:Llyiahf/vczjk/n62;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n62;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dj2;->OooOOo0:Llyiahf/vczjk/n62;

    const/16 p1, 0x15

    invoke-direct {p0, p1}, Llyiahf/vczjk/n62;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final o000OOo(Llyiahf/vczjk/y85;)Ljava/lang/Object;
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/dj2;->OooOOo0:Llyiahf/vczjk/n62;

    iget-object p1, p1, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/go8;

    check-cast p1, Ljava/lang/Float;

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    const v0, 0x40233333    # 2.55f

    mul-float/2addr p1, v0

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    return-object p1
.end method
