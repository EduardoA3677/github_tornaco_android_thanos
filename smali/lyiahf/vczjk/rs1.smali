.class public final Llyiahf/vczjk/rs1;
.super Llyiahf/vczjk/ph8;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _annotated:Llyiahf/vczjk/vm;

.field protected final _creatorIndex:I

.field protected _fallbackSetter:Llyiahf/vczjk/ph8;

.field protected _ignorable:Z

.field protected final _injectableValue:Llyiahf/vczjk/t54;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rs1;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    iget-object p2, p1, Llyiahf/vczjk/rs1;->_annotated:Llyiahf/vczjk/vm;

    iput-object p2, p0, Llyiahf/vczjk/rs1;->_annotated:Llyiahf/vczjk/vm;

    iget-object p2, p1, Llyiahf/vczjk/rs1;->_injectableValue:Llyiahf/vczjk/t54;

    iput-object p2, p0, Llyiahf/vczjk/rs1;->_injectableValue:Llyiahf/vczjk/t54;

    iget-object p2, p1, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    iput-object p2, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    iget p2, p1, Llyiahf/vczjk/rs1;->_creatorIndex:I

    iput p2, p0, Llyiahf/vczjk/rs1;->_creatorIndex:I

    iget-boolean p1, p1, Llyiahf/vczjk/rs1;->_ignorable:Z

    iput-boolean p1, p0, Llyiahf/vczjk/rs1;->_ignorable:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/rs1;Llyiahf/vczjk/xa7;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/xa7;)V

    iget-object p2, p1, Llyiahf/vczjk/rs1;->_annotated:Llyiahf/vczjk/vm;

    iput-object p2, p0, Llyiahf/vczjk/rs1;->_annotated:Llyiahf/vczjk/vm;

    iget-object p2, p1, Llyiahf/vczjk/rs1;->_injectableValue:Llyiahf/vczjk/t54;

    iput-object p2, p0, Llyiahf/vczjk/rs1;->_injectableValue:Llyiahf/vczjk/t54;

    iget-object p2, p1, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    iput-object p2, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    iget p2, p1, Llyiahf/vczjk/rs1;->_creatorIndex:I

    iput p2, p0, Llyiahf/vczjk/rs1;->_creatorIndex:I

    iget-boolean p1, p1, Llyiahf/vczjk/rs1;->_ignorable:Z

    iput-boolean p1, p0, Llyiahf/vczjk/rs1;->_ignorable:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;Llyiahf/vczjk/vm;ILlyiahf/vczjk/t54;Llyiahf/vczjk/wa7;)V
    .locals 7

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object v5, p5

    move-object/from16 v6, p9

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;Llyiahf/vczjk/wa7;)V

    iput-object p6, p0, Llyiahf/vczjk/rs1;->_annotated:Llyiahf/vczjk/vm;

    iput p7, p0, Llyiahf/vczjk/rs1;->_creatorIndex:I

    iput-object p8, p0, Llyiahf/vczjk/rs1;->_injectableValue:Llyiahf/vczjk/t54;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/rs1;->Oooo00O()V

    iget-object v0, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p3, p1}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO00o()Llyiahf/vczjk/pm;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rs1;->_annotated:Llyiahf/vczjk/vm;

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/wa7;
    .locals 2

    invoke-super {p0}, Llyiahf/vczjk/lh1;->OooO0O0()Llyiahf/vczjk/wa7;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/lh1;->OooO0O0()Llyiahf/vczjk/wa7;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/wa7;->OooOOO0:Llyiahf/vczjk/pc0;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/wa7;->OooO0OO(Llyiahf/vczjk/pc0;)Llyiahf/vczjk/wa7;

    move-result-object v0

    :cond_0
    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/rs1;->Oooo00O()V

    iget-object v0, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p3, p1}, Llyiahf/vczjk/ph8;->OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0o(Llyiahf/vczjk/t72;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ph8;->OooOO0o(Llyiahf/vczjk/t72;)V

    :cond_0
    return-void
.end method

.method public final OooOOO()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rs1;->_injectableValue:Llyiahf/vczjk/t54;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/t54;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOO0()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/rs1;->_creatorIndex:I

    return v0
.end method

.method public final OooOo()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/rs1;->_ignorable:Z

    return-void
.end method

.method public final OooOo0O()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/rs1;->_ignorable:Z

    return v0
.end method

.method public final OooOo0o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rs1;->_injectableValue:Llyiahf/vczjk/t54;

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/t54;->_useInput:Ljava/lang/Boolean;

    if-nez v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    :goto_0
    if-nez v0, :cond_1

    const/4 v0, 0x1

    return v0

    :cond_1
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/rs1;->Oooo00O()V

    iget-object v0, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ph8;->OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/rs1;->Oooo00O()V

    iget-object v0, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void
.end method

.method public final OooOoo(Llyiahf/vczjk/xa7;)Llyiahf/vczjk/ph8;
    .locals 1

    new-instance v0, Llyiahf/vczjk/rs1;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/rs1;-><init>(Llyiahf/vczjk/rs1;Llyiahf/vczjk/xa7;)V

    return-object v0
.end method

.method public final OooOooO(Llyiahf/vczjk/u46;)Llyiahf/vczjk/ph8;
    .locals 2

    new-instance v0, Llyiahf/vczjk/rs1;

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-direct {v0, p0, v1, p1}, Llyiahf/vczjk/rs1;-><init>(Llyiahf/vczjk/rs1;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

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
    new-instance v0, Llyiahf/vczjk/rs1;

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/rs1;-><init>(Llyiahf/vczjk/rs1;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    return-object v0
.end method

.method public final Oooo00O()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/rs1;->_fallbackSetter:Llyiahf/vczjk/ph8;

    if-eqz v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "No fallback setter/field defined for creator property \'"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v1}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\'"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    new-instance v2, Llyiahf/vczjk/d44;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0, v1}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    throw v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[creator property, name \'"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v1}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\'; inject id \'"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/rs1;->OooOOO()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "\']"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
