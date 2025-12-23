.class public final Llyiahf/vczjk/ux2;
.super Llyiahf/vczjk/ph8;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public final transient OooOOOO:Ljava/lang/reflect/Field;

.field protected final _annotated:Llyiahf/vczjk/mm;

.field protected final _skipNulls:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb0;Llyiahf/vczjk/x64;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;Llyiahf/vczjk/mm;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/eb0;Llyiahf/vczjk/x64;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;)V

    iput-object p5, p0, Llyiahf/vczjk/ux2;->_annotated:Llyiahf/vczjk/mm;

    iget-object p1, p5, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    iput-object p1, p0, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    iget-object p1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-static {p1}, Llyiahf/vczjk/f56;->OooO00o(Llyiahf/vczjk/u46;)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/ux2;->_skipNulls:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ux2;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;)V

    iget-object v0, p1, Llyiahf/vczjk/ux2;->_annotated:Llyiahf/vczjk/mm;

    iput-object v0, p0, Llyiahf/vczjk/ux2;->_annotated:Llyiahf/vczjk/mm;

    iget-object v0, v0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    if-eqz v0, :cond_0

    iput-object v0, p0, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    iget-boolean p1, p1, Llyiahf/vczjk/ux2;->_skipNulls:Z

    iput-boolean p1, p0, Llyiahf/vczjk/ux2;->_skipNulls:Z

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Missing field (broken JDK (de)serialization?)"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public constructor <init>(Llyiahf/vczjk/ux2;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    iget-object p2, p1, Llyiahf/vczjk/ux2;->_annotated:Llyiahf/vczjk/mm;

    iput-object p2, p0, Llyiahf/vczjk/ux2;->_annotated:Llyiahf/vczjk/mm;

    iget-object p1, p1, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    iput-object p1, p0, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-static {p3}, Llyiahf/vczjk/f56;->OooO00o(Llyiahf/vczjk/u46;)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/ux2;->_skipNulls:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ux2;Llyiahf/vczjk/xa7;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/xa7;)V

    iget-object p2, p1, Llyiahf/vczjk/ux2;->_annotated:Llyiahf/vczjk/mm;

    iput-object p2, p0, Llyiahf/vczjk/ux2;->_annotated:Llyiahf/vczjk/mm;

    iget-object p2, p1, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    iput-object p2, p0, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    iget-boolean p1, p1, Llyiahf/vczjk/ux2;->_skipNulls:Z

    iput-boolean p1, p0, Llyiahf/vczjk/ux2;->_skipNulls:Z

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/ux2;->_skipNulls:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v0, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    goto :goto_1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_3

    iget-boolean v0, p0, Llyiahf/vczjk/ux2;->_skipNulls:Z

    if-eqz v0, :cond_2

    :goto_0
    return-void

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v0, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    goto :goto_1

    :cond_3
    move-object p2, v0

    goto :goto_1

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p1, p2, v0}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p2

    :goto_1
    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-virtual {v0, p3, p2}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p3

    invoke-virtual {p0, p1, p3, p2}, Llyiahf/vczjk/ph8;->OooO0o(Llyiahf/vczjk/eb4;Ljava/lang/Exception;Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO00o()Llyiahf/vczjk/pm;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ux2;->_annotated:Llyiahf/vczjk/mm;

    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/ux2;->_skipNulls:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v0, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    goto :goto_1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_3

    iget-boolean v0, p0, Llyiahf/vczjk/ux2;->_skipNulls:Z

    if-eqz v0, :cond_2

    :goto_0
    return-object p3

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v0, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p2

    goto :goto_1

    :cond_3
    move-object p2, v0

    goto :goto_1

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p1, p2, v0}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p2

    :goto_1
    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-virtual {v0, p3, p2}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p3

    :catch_0
    move-exception p3

    invoke-virtual {p0, p1, p3, p2}, Llyiahf/vczjk/ph8;->OooO0o(Llyiahf/vczjk/eb4;Ljava/lang/Exception;Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOO0o(Llyiahf/vczjk/t72;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-static {v0, p1}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    return-void
.end method

.method public final OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-virtual {v0, p1, p2}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    const/4 v0, 0x0

    invoke-virtual {p0, v0, p1, p2}, Llyiahf/vczjk/ph8;->OooO0o(Llyiahf/vczjk/eb4;Ljava/lang/Exception;Ljava/lang/Object;)V

    throw v0
.end method

.method public final OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/ux2;->OooOOOO:Ljava/lang/reflect/Field;

    invoke-virtual {v0, p1, p2}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p1

    const/4 v0, 0x0

    invoke-virtual {p0, v0, p1, p2}, Llyiahf/vczjk/ph8;->OooO0o(Llyiahf/vczjk/eb4;Ljava/lang/Exception;Ljava/lang/Object;)V

    throw v0
.end method

.method public final OooOoo(Llyiahf/vczjk/xa7;)Llyiahf/vczjk/ph8;
    .locals 1

    new-instance v0, Llyiahf/vczjk/ux2;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/ux2;-><init>(Llyiahf/vczjk/ux2;Llyiahf/vczjk/xa7;)V

    return-object v0
.end method

.method public final OooOooO(Llyiahf/vczjk/u46;)Llyiahf/vczjk/ph8;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ux2;

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-direct {v0, p0, v1, p1}, Llyiahf/vczjk/ux2;-><init>(Llyiahf/vczjk/ux2;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

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
    new-instance v0, Llyiahf/vczjk/ux2;

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/ux2;-><init>(Llyiahf/vczjk/ux2;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    return-object v0
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 1

    new-instance v0, Llyiahf/vczjk/ux2;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ux2;-><init>(Llyiahf/vczjk/ux2;)V

    return-object v0
.end method
