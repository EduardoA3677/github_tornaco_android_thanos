.class public final Llyiahf/vczjk/ck0;
.super Llyiahf/vczjk/zb0;
.source "SourceFile"


# static fields
.field public static final OooO0o:Llyiahf/vczjk/ck0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/ck0;

    const/4 v1, 0x1

    const/4 v2, 0x0

    const/4 v3, 0x7

    filled-new-array {v1, v2, v3}, [I

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/ck0;-><init>([I)V

    sput-object v0, Llyiahf/vczjk/ck0;->OooO0o:Llyiahf/vczjk/ck0;

    new-instance v0, Llyiahf/vczjk/ck0;

    new-array v1, v2, [I

    invoke-direct {v0, v1}, Llyiahf/vczjk/ck0;-><init>([I)V

    return-void
.end method

.method public varargs constructor <init>([I)V
    .locals 1

    const-string v0, "numbers"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object p1

    invoke-direct {p0, p1}, Llyiahf/vczjk/zb0;-><init>([I)V

    return-void
.end method
