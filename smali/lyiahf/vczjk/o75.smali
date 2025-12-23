.class public final Llyiahf/vczjk/o75;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $progress$delegate:Llyiahf/vczjk/s75;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a75;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o75;->$progress$delegate:Llyiahf/vczjk/s75;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o75;->$progress$delegate:Llyiahf/vczjk/s75;

    check-cast v0, Llyiahf/vczjk/k75;

    invoke-virtual {v0}, Llyiahf/vczjk/k75;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0
.end method
