.class public final Llyiahf/vczjk/v62;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $calculationLevelRef:Llyiahf/vczjk/z14;

.field final synthetic $nestedCalculationLevel:I

.field final synthetic $newDependencies:Llyiahf/vczjk/zr5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zr5;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/w62;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/w62;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w62;Llyiahf/vczjk/z14;Llyiahf/vczjk/zr5;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/v62;->this$0:Llyiahf/vczjk/w62;

    iput-object p2, p0, Llyiahf/vczjk/v62;->$calculationLevelRef:Llyiahf/vczjk/z14;

    iput-object p3, p0, Llyiahf/vczjk/v62;->$newDependencies:Llyiahf/vczjk/zr5;

    iput p4, p0, Llyiahf/vczjk/v62;->$nestedCalculationLevel:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/v62;->this$0:Llyiahf/vczjk/w62;

    if-eq p1, v0, :cond_2

    instance-of v0, p1, Llyiahf/vczjk/b39;

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/v62;->$calculationLevelRef:Llyiahf/vczjk/z14;

    iget v0, v0, Llyiahf/vczjk/z14;->OooO00o:I

    iget-object v1, p0, Llyiahf/vczjk/v62;->$newDependencies:Llyiahf/vczjk/zr5;

    iget v2, p0, Llyiahf/vczjk/v62;->$nestedCalculationLevel:I

    sub-int/2addr v0, v2

    invoke-virtual {v1, p1}, Llyiahf/vczjk/zr5;->OooO0Oo(Ljava/lang/Object;)I

    move-result v2

    if-ltz v2, :cond_0

    iget-object v3, v1, Llyiahf/vczjk/zr5;->OooO0OO:[I

    aget v2, v3, v2

    goto :goto_0

    :cond_0
    const v2, 0x7fffffff

    :goto_0
    invoke-static {v0, v2}, Ljava/lang/Math;->min(II)I

    move-result v0

    invoke-virtual {v1, v0, p1}, Llyiahf/vczjk/zr5;->OooO0oO(ILjava/lang/Object;)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "A derived state calculation cannot read itself"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
