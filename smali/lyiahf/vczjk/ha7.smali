.class public final Llyiahf/vczjk/ha7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $steps:I

.field final synthetic $value:F

.field final synthetic $valueRange:Llyiahf/vczjk/n01;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/n01;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(FILlyiahf/vczjk/m01;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/ha7;->$value:F

    iput-object p3, p0, Llyiahf/vczjk/ha7;->$valueRange:Llyiahf/vczjk/n01;

    iput p2, p0, Llyiahf/vczjk/ha7;->$steps:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/af8;

    new-instance v0, Llyiahf/vczjk/o97;

    iget v1, p0, Llyiahf/vczjk/ha7;->$value:F

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/ha7;->$valueRange:Llyiahf/vczjk/n01;

    invoke-static {v1, v2}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/ha7;->$valueRange:Llyiahf/vczjk/n01;

    iget v3, p0, Llyiahf/vczjk/ha7;->$steps:I

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/o97;-><init>(FLlyiahf/vczjk/n01;I)V

    sget-object v1, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v1, Llyiahf/vczjk/ve8;->OooO0OO:Llyiahf/vczjk/ze8;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/4 v3, 0x1

    aget-object v2, v2, v3

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
