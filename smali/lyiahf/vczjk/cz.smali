.class public final Llyiahf/vczjk/cz;
.super Llyiahf/vczjk/xy;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _inclusion:Llyiahf/vczjk/kc4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cz;Llyiahf/vczjk/db0;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/v3a;-><init>(Llyiahf/vczjk/v3a;Llyiahf/vczjk/db0;)V

    iget-object p1, p1, Llyiahf/vczjk/cz;->_inclusion:Llyiahf/vczjk/kc4;

    iput-object p1, p0, Llyiahf/vczjk/cz;->_inclusion:Llyiahf/vczjk/kc4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/d4a;Ljava/lang/String;ZLlyiahf/vczjk/x64;Llyiahf/vczjk/kc4;)V
    .locals 0

    invoke-direct/range {p0 .. p5}, Llyiahf/vczjk/v3a;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/d4a;Ljava/lang/String;ZLlyiahf/vczjk/x64;)V

    move-object p1, p0

    iput-object p6, p1, Llyiahf/vczjk/cz;->_inclusion:Llyiahf/vczjk/kc4;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xy;->OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/cz;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooO0oO()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000OO0()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/v3a;->OooOO0O(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooOo()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    const/4 v2, 0x0

    if-ne v0, v1, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    goto :goto_0

    :cond_1
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-eq v0, v1, :cond_2

    invoke-virtual {p0, p2, p1, v2}, Llyiahf/vczjk/cz;->OooOOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/tt9;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    :goto_0
    sget-object v1, Llyiahf/vczjk/gc5;->OooOooo:Llyiahf/vczjk/gc5;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/v72;->o0000O00(Llyiahf/vczjk/gc5;)Z

    move-result v1

    :goto_1
    sget-object v3, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v3, :cond_9

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    iget-object v3, p0, Llyiahf/vczjk/v3a;->_typePropertyName:Ljava/lang/String;

    invoke-virtual {v0, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_5

    if-eqz v1, :cond_3

    iget-object v3, p0, Llyiahf/vczjk/v3a;->_typePropertyName:Ljava/lang/String;

    invoke-virtual {v0, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v3

    if-eqz v3, :cond_3

    goto :goto_2

    :cond_3
    if-nez v2, :cond_4

    new-instance v2, Llyiahf/vczjk/tt9;

    invoke-direct {v2, p1, p2}, Llyiahf/vczjk/tt9;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    :cond_4
    invoke-virtual {v2, v0}, Llyiahf/vczjk/tt9;->o0000Ooo(Ljava/lang/String;)V

    invoke-virtual {v2, p2}, Llyiahf/vczjk/tt9;->o000O0oO(Llyiahf/vczjk/eb4;)V

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    goto :goto_1

    :cond_5
    :goto_2
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/v3a;->OooOOO0(Ljava/lang/String;Llyiahf/vczjk/v72;)Llyiahf/vczjk/e94;

    move-result-object v1

    iget-boolean v3, p0, Llyiahf/vczjk/v3a;->_typeIdVisible:Z

    if-eqz v3, :cond_7

    if-nez v2, :cond_6

    new-instance v2, Llyiahf/vczjk/tt9;

    invoke-direct {v2, p1, p2}, Llyiahf/vczjk/tt9;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    :cond_6
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/tt9;->o0000Ooo(Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Llyiahf/vczjk/tt9;->o0000ooO(Ljava/lang/String;)V

    :cond_7
    if-eqz v2, :cond_8

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooOOOO()V

    invoke-virtual {v2, p2}, Llyiahf/vczjk/tt9;->o000O0O0(Llyiahf/vczjk/eb4;)Llyiahf/vczjk/rt9;

    move-result-object v0

    invoke-static {v0, p2}, Llyiahf/vczjk/gb4;->o000Oo0(Llyiahf/vczjk/rt9;Llyiahf/vczjk/eb4;)Llyiahf/vczjk/gb4;

    move-result-object p2

    :cond_8
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_9
    invoke-virtual {p0, p2, p1, v2}, Llyiahf/vczjk/cz;->OooOOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/tt9;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/u3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v3a;->_property:Llyiahf/vczjk/db0;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/cz;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/cz;-><init>(Llyiahf/vczjk/cz;Llyiahf/vczjk/db0;)V

    return-object v0
.end method

.method public final OooOO0()Llyiahf/vczjk/kc4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cz;->_inclusion:Llyiahf/vczjk/kc4;

    return-object v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/tt9;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0, p2}, Llyiahf/vczjk/v3a;->OooOO0o(Llyiahf/vczjk/v72;)Llyiahf/vczjk/e94;

    move-result-object v0

    if-nez v0, :cond_5

    iget-object p3, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    invoke-static {p3, p1}, Llyiahf/vczjk/u3a;->OooO00o(Llyiahf/vczjk/x64;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p3

    if-eqz p3, :cond_0

    return-object p3

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result p3

    if-eqz p3, :cond_1

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/xy;->OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    sget-object p3, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, p3}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result p3

    const/4 v0, 0x0

    if-eqz p3, :cond_2

    sget-object p3, Llyiahf/vczjk/w72;->Oooo000:Llyiahf/vczjk/w72;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p3

    if-eqz p3, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_2

    return-object v0

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/v3a;->_typePropertyName:Ljava/lang/String;

    const-string p3, "missing type id property \'"

    const-string v0, "\'"

    invoke-static {p3, p1, v0}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    iget-object p3, p0, Llyiahf/vczjk/v3a;->_property:Llyiahf/vczjk/db0;

    if-eqz p3, :cond_3

    invoke-interface {p3}, Llyiahf/vczjk/yt5;->getName()Ljava/lang/String;

    move-result-object p3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " (for POJO property \'"

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "\')"

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    :cond_3
    iget-object p3, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    iget-object v0, p2, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object v0, v0, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    if-eqz v0, :cond_4

    iget-object p1, v0, Llyiahf/vczjk/j05;->OooO00o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0O0(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_4
    const-string v0, "Missing type id when trying to resolve subtype of %s"

    filled-new-array {p3}, [Ljava/lang/Object;

    move-result-object v1

    invoke-static {v0, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, p1}, Llyiahf/vczjk/mc4;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/k44;

    iget-object p2, p2, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    const/4 v1, 0x0

    invoke-direct {v0, p2, p1, p3, v1}, Llyiahf/vczjk/k44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;Ljava/lang/String;)V

    throw v0

    :cond_5
    if-eqz p3, :cond_6

    invoke-virtual {p3}, Llyiahf/vczjk/tt9;->o00000o0()V

    invoke-virtual {p3, p1}, Llyiahf/vczjk/tt9;->o000O0O0(Llyiahf/vczjk/eb4;)Llyiahf/vczjk/rt9;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    :cond_6
    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
