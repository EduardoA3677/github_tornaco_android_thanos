.class public final Llyiahf/vczjk/u66;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
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

.field protected final _idType:Llyiahf/vczjk/x64;

.field public final generator:Llyiahf/vczjk/p66;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p66;"
        }
    .end annotation
.end field

.field public final idProperty:Llyiahf/vczjk/ph8;

.field public final propertyName:Llyiahf/vczjk/xa7;

.field public final resolver:Llyiahf/vczjk/x66;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/p66;Llyiahf/vczjk/e94;Llyiahf/vczjk/ph8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/u66;->_idType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/u66;->propertyName:Llyiahf/vczjk/xa7;

    iput-object p3, p0, Llyiahf/vczjk/u66;->generator:Llyiahf/vczjk/p66;

    iput-object p4, p0, Llyiahf/vczjk/u66;->_deserializer:Llyiahf/vczjk/e94;

    iput-object p5, p0, Llyiahf/vczjk/u66;->idProperty:Llyiahf/vczjk/ph8;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u66;->_deserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
