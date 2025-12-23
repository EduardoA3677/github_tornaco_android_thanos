.class public final Llyiahf/vczjk/bi7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Closeable;
.implements Ljava/lang/AutoCloseable;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/zb2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zb2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bi7;->OooOOO0:Llyiahf/vczjk/zb2;

    return-void
.end method


# virtual methods
.method public final close()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bi7;->OooOOO0:Llyiahf/vczjk/zb2;

    invoke-virtual {v0}, Llyiahf/vczjk/zb2;->close()V

    return-void
.end method
