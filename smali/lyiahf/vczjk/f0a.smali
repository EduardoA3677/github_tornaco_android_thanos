.class public final Llyiahf/vczjk/f0a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/s1a;


# instance fields
.field public final OooOOO:Z

.field public final OooOOO0:Lcom/google/gson/reflect/TypeToken;

.field public final OooOOOO:Llyiahf/vczjk/k87;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k87;Lcom/google/gson/reflect/TypeToken;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/f0a;->OooOOOO:Llyiahf/vczjk/k87;

    iput-object p2, p0, Llyiahf/vczjk/f0a;->OooOOO0:Lcom/google/gson/reflect/TypeToken;

    iput-boolean p3, p0, Llyiahf/vczjk/f0a;->OooOOO:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nk3;Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;
    .locals 9

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/f0a;->OooOOO0:Lcom/google/gson/reflect/TypeToken;

    if-eqz v1, :cond_2

    invoke-virtual {v1, p2}, Lcom/google/gson/reflect/TypeToken;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1

    iget-boolean v2, p0, Llyiahf/vczjk/f0a;->OooOOO:Z

    if-eqz v2, :cond_0

    invoke-virtual {v1}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    move-result-object v1

    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    move-result-object v2

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    return-object v0

    :cond_1
    :goto_0
    new-instance v3, Llyiahf/vczjk/g0a;

    const/4 v8, 0x1

    iget-object v4, p0, Llyiahf/vczjk/f0a;->OooOOOO:Llyiahf/vczjk/k87;

    move-object v7, p0

    move-object v5, p1

    move-object v6, p2

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/g0a;-><init>(Llyiahf/vczjk/k87;Llyiahf/vczjk/nk3;Lcom/google/gson/reflect/TypeToken;Llyiahf/vczjk/s1a;Z)V

    return-object v3

    :cond_2
    move-object v6, p2

    invoke-virtual {v6}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    throw v0
.end method
