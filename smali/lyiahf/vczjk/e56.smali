.class public final Llyiahf/vczjk/e56;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u46;
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _deserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/e94;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/e56;->_deserializer:Llyiahf/vczjk/e94;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/e56;->_deserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/e94;->OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
