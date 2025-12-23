.class public final Llyiahf/vczjk/su8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $onRemainingScrollOffsetUpdate:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $remainingScrollOffset:Llyiahf/vczjk/el7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/su8;->$remainingScrollOffset:Llyiahf/vczjk/el7;

    iput-object p2, p0, Llyiahf/vczjk/su8;->$onRemainingScrollOffsetUpdate:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/su8;->$remainingScrollOffset:Llyiahf/vczjk/el7;

    iget v1, v0, Llyiahf/vczjk/el7;->element:F

    sub-float/2addr v1, p1

    iput v1, v0, Llyiahf/vczjk/el7;->element:F

    iget-object p1, p0, Llyiahf/vczjk/su8;->$onRemainingScrollOffsetUpdate:Llyiahf/vczjk/oe3;

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
