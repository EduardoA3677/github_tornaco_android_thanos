.class public final Llyiahf/vczjk/be3;
.super Ljava/lang/RuntimeException;
.source "SourceFile"


# instance fields
.field private final callbackName:Llyiahf/vczjk/ce3;

.field private final cause:Ljava/lang/Throwable;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ce3;Ljava/lang/Throwable;)V
    .locals 0

    invoke-direct {p0, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    iput-object p1, p0, Llyiahf/vczjk/be3;->callbackName:Llyiahf/vczjk/ce3;

    iput-object p2, p0, Llyiahf/vczjk/be3;->cause:Ljava/lang/Throwable;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/ce3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/be3;->callbackName:Llyiahf/vczjk/ce3;

    return-object v0
.end method

.method public final getCause()Ljava/lang/Throwable;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/be3;->cause:Ljava/lang/Throwable;

    return-object v0
.end method
