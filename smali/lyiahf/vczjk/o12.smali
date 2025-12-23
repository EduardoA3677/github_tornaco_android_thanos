.class public Llyiahf/vczjk/o12;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/s1a;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nk3;Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;
    .locals 1

    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    move-result-object p1

    const-class p2, Ljava/util/Date;

    if-ne p1, p2, :cond_0

    new-instance p1, Llyiahf/vczjk/r12;

    sget-object p2, Llyiahf/vczjk/q12;->OooO0O0:Llyiahf/vczjk/p12;

    const/4 v0, 0x2

    invoke-direct {p1, p2, v0, v0}, Llyiahf/vczjk/r12;-><init>(Llyiahf/vczjk/q12;II)V

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "DefaultDateTypeAdapter#DEFAULT_STYLE_FACTORY"

    return-object v0
.end method
