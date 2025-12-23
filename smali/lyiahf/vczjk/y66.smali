.class public final Llyiahf/vczjk/y66;
.super Llyiahf/vczjk/ph8;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _objectIdReader:Llyiahf/vczjk/u66;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u66;Llyiahf/vczjk/wa7;)V
    .locals 3

    iget-object v0, p1, Llyiahf/vczjk/u66;->propertyName:Llyiahf/vczjk/xa7;

    iget-object v1, p1, Llyiahf/vczjk/u66;->_idType:Llyiahf/vczjk/x64;

    iget-object v2, p1, Llyiahf/vczjk/u66;->_deserializer:Llyiahf/vczjk/e94;

    invoke-direct {p0, v0, v1, p2, v2}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/wa7;Llyiahf/vczjk/e94;)V

    iput-object p1, p0, Llyiahf/vczjk/y66;->_objectIdReader:Llyiahf/vczjk/u66;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/y66;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    iget-object p1, p1, Llyiahf/vczjk/y66;->_objectIdReader:Llyiahf/vczjk/u66;

    iput-object p1, p0, Llyiahf/vczjk/y66;->_objectIdReader:Llyiahf/vczjk/u66;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/y66;Llyiahf/vczjk/xa7;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/xa7;)V

    iget-object p1, p1, Llyiahf/vczjk/y66;->_objectIdReader:Llyiahf/vczjk/u66;

    iput-object p1, p0, Llyiahf/vczjk/y66;->_objectIdReader:Llyiahf/vczjk/u66;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    .locals 0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/y66;->OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final OooO00o()Llyiahf/vczjk/pm;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object p3, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, p3}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result p3

    const/4 v0, 0x0

    if-eqz p3, :cond_0

    return-object v0

    :cond_0
    iget-object p3, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    iget-object p3, p0, Llyiahf/vczjk/y66;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object p3, p3, Llyiahf/vczjk/u66;->generator:Llyiahf/vczjk/p66;

    invoke-virtual {p2, p1, p3}, Llyiahf/vczjk/v72;->o00Ooo(Ljava/lang/Object;Llyiahf/vczjk/p66;)Llyiahf/vczjk/bh7;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    throw v0
.end method

.method public final OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/y66;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object v0, v0, Llyiahf/vczjk/u66;->idProperty:Llyiahf/vczjk/ph8;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ph8;->OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Should not call set() on ObjectIdProperty that has no SettableBeanProperty"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/y66;->OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final OooOoo(Llyiahf/vczjk/xa7;)Llyiahf/vczjk/ph8;
    .locals 1

    new-instance v0, Llyiahf/vczjk/y66;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/y66;-><init>(Llyiahf/vczjk/y66;Llyiahf/vczjk/xa7;)V

    return-object v0
.end method

.method public final OooOooO(Llyiahf/vczjk/u46;)Llyiahf/vczjk/ph8;
    .locals 2

    new-instance v0, Llyiahf/vczjk/y66;

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-direct {v0, p0, v1, p1}, Llyiahf/vczjk/y66;-><init>(Llyiahf/vczjk/y66;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    return-object v0
.end method

.method public final Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-ne v0, p1, :cond_0

    return-object p0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    if-ne v0, v1, :cond_1

    move-object v1, p1

    :cond_1
    new-instance v0, Llyiahf/vczjk/y66;

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/y66;-><init>(Llyiahf/vczjk/y66;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    return-object v0
.end method
