.class public final Llyiahf/vczjk/f59;
.super Llyiahf/vczjk/nca;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected _arrayDelegateArguments:[Llyiahf/vczjk/ph8;

.field protected _arrayDelegateCreator:Llyiahf/vczjk/gn;

.field protected _arrayDelegateType:Llyiahf/vczjk/x64;

.field protected _constructorArguments:[Llyiahf/vczjk/ph8;

.field protected _defaultCreator:Llyiahf/vczjk/gn;

.field protected _delegateArguments:[Llyiahf/vczjk/ph8;

.field protected _delegateCreator:Llyiahf/vczjk/gn;

.field protected _delegateType:Llyiahf/vczjk/x64;

.field protected _fromBooleanCreator:Llyiahf/vczjk/gn;

.field protected _fromDoubleCreator:Llyiahf/vczjk/gn;

.field protected _fromIntCreator:Llyiahf/vczjk/gn;

.field protected _fromLongCreator:Llyiahf/vczjk/gn;

.field protected _fromStringCreator:Llyiahf/vczjk/gn;

.field protected _incompleteParameter:Llyiahf/vczjk/vm;

.field protected final _valueClass:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field

.field protected final _valueTypeDesc:Ljava/lang/String;

.field protected _withArgsCreator:Llyiahf/vczjk/gn;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x64;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-nez p1, :cond_0

    const-string v0, "UNKNOWN TYPE"

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/x64;->toString()Ljava/lang/String;

    move-result-object v0

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/f59;->_valueTypeDesc:Ljava/lang/String;

    if-nez p1, :cond_1

    const-class p1, Ljava/lang/Object;

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    :goto_1
    iput-object p1, p0, Llyiahf/vczjk/f59;->_valueClass:Ljava/lang/Class;

    return-void
.end method


# virtual methods
.method public final OooO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_defaultCreator:Llyiahf/vczjk/gn;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromBooleanCreator:Llyiahf/vczjk/gn;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0OO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromDoubleCreator:Llyiahf/vczjk/gn;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0Oo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromIntCreator:Llyiahf/vczjk/gn;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_withArgsCreator:Llyiahf/vczjk/gn;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0o0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromLongCreator:Llyiahf/vczjk/gn;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0oO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromStringCreator:Llyiahf/vczjk/gn;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0oo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_arrayDelegateType:Llyiahf/vczjk/x64;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOO0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_delegateType:Llyiahf/vczjk/x64;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOO0O()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/f59;->OooO()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/f59;->OooOO0()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/f59;->OooO0oo()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/f59;->OooO0o()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/f59;->OooO0oO()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/f59;->OooO0Oo()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/f59;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/f59;->OooO0OO()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/f59;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final OooOO0o(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromBooleanCreator:Llyiahf/vczjk/gn;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p2

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromBooleanCreator:Llyiahf/vczjk/gn;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/gn;->o0O0O00(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p1

    :catchall_0
    move-exception p2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromBooleanCreator:Llyiahf/vczjk/gn;

    invoke-virtual {v0}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/f59;->OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;

    move-result-object p2

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    throw v1

    :cond_0
    invoke-super {p0, p1, p2}, Llyiahf/vczjk/nca;->OooOO0o(Llyiahf/vczjk/v72;Z)Ljava/lang/Object;

    throw v1
.end method

.method public final OooOOO(Llyiahf/vczjk/v72;I)Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromIntCreator:Llyiahf/vczjk/gn;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromIntCreator:Llyiahf/vczjk/gn;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/gn;->o0O0O00(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p1

    :catchall_0
    move-exception p2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromIntCreator:Llyiahf/vczjk/gn;

    invoke-virtual {v0}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/f59;->OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;

    move-result-object p2

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    throw v1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromLongCreator:Llyiahf/vczjk/gn;

    if-eqz v0, :cond_1

    int-to-long v2, p2

    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    :try_start_1
    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromLongCreator:Llyiahf/vczjk/gn;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/gn;->o0O0O00(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    return-object p1

    :catchall_1
    move-exception p2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromLongCreator:Llyiahf/vczjk/gn;

    invoke-virtual {v0}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/f59;->OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;

    move-result-object p2

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    throw v1

    :cond_1
    invoke-super {p0, p1, p2}, Llyiahf/vczjk/nca;->OooOOO(Llyiahf/vczjk/v72;I)Ljava/lang/Object;

    throw v1
.end method

.method public final OooOOO0(Llyiahf/vczjk/v72;D)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromDoubleCreator:Llyiahf/vczjk/gn;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-static {p2, p3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p2

    :try_start_0
    iget-object p3, p0, Llyiahf/vczjk/f59;->_fromDoubleCreator:Llyiahf/vczjk/gn;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/gn;->o0O0O00(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p1

    :catchall_0
    move-exception p2

    iget-object p3, p0, Llyiahf/vczjk/f59;->_fromDoubleCreator:Llyiahf/vczjk/gn;

    invoke-virtual {p3}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object p3

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/f59;->OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;

    move-result-object p2

    invoke-virtual {p1, p3, p2}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    throw v1

    :cond_0
    invoke-super {p0, p1, p2, p3}, Llyiahf/vczjk/nca;->OooOOO0(Llyiahf/vczjk/v72;D)Ljava/lang/Object;

    throw v1
.end method

.method public final OooOOOO(Llyiahf/vczjk/v72;J)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromLongCreator:Llyiahf/vczjk/gn;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    :try_start_0
    iget-object p3, p0, Llyiahf/vczjk/f59;->_fromLongCreator:Llyiahf/vczjk/gn;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/gn;->o0O0O00(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p1

    :catchall_0
    move-exception p2

    iget-object p3, p0, Llyiahf/vczjk/f59;->_fromLongCreator:Llyiahf/vczjk/gn;

    invoke-virtual {p3}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object p3

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/f59;->OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;

    move-result-object p2

    invoke-virtual {p1, p3, p2}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    throw v1

    :cond_0
    invoke-super {p0, p1, p2, p3}, Llyiahf/vczjk/nca;->OooOOOO(Llyiahf/vczjk/v72;J)Ljava/lang/Object;

    throw v1
.end method

.method public final OooOOOo(Llyiahf/vczjk/v72;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_withArgsCreator:Llyiahf/vczjk/gn;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    :try_start_0
    invoke-virtual {v0, p2}, Llyiahf/vczjk/gn;->oo0o0Oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/f59;->OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;

    move-result-object p2

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    throw v1

    :cond_0
    invoke-super {p0, p1, p2}, Llyiahf/vczjk/nca;->OooOOOo(Llyiahf/vczjk/v72;[Ljava/lang/Object;)Ljava/lang/Object;

    throw v1
.end method

.method public final OooOOo(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_arrayDelegateCreator:Llyiahf/vczjk/gn;

    if-nez v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/f59;->_delegateCreator:Llyiahf/vczjk/gn;

    if-eqz v1, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/f59;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/f59;->_arrayDelegateArguments:[Llyiahf/vczjk/ph8;

    invoke-virtual {p0, v0, v1, p2, p1}, Llyiahf/vczjk/f59;->OooOoo(Llyiahf/vczjk/gn;[Llyiahf/vczjk/ph8;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromStringCreator:Llyiahf/vczjk/gn;

    if-nez v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/nca;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    :try_start_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/gn;->o0O0O00(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p1

    :catchall_0
    move-exception p1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_fromStringCreator:Llyiahf/vczjk/gn;

    invoke-virtual {v0}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/f59;->OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;

    move-result-object p1

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/f59;->_defaultCreator:Llyiahf/vczjk/gn;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    :try_start_0
    invoke-virtual {v0}, Llyiahf/vczjk/gn;->o0OO00O()Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception v0

    iget-object v2, p0, Llyiahf/vczjk/f59;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/f59;->OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;

    move-result-object v0

    invoke-virtual {p1, v2, v0}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    throw v1

    :cond_0
    invoke-super {p0, p1}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    throw v1
.end method

.method public final OooOo()Llyiahf/vczjk/gn;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_delegateCreator:Llyiahf/vczjk/gn;

    return-object v0
.end method

.method public final OooOo0()Llyiahf/vczjk/gn;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_arrayDelegateCreator:Llyiahf/vczjk/gn;

    return-object v0
.end method

.method public final OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f59;->_delegateCreator:Llyiahf/vczjk/gn;

    if-nez v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/f59;->_arrayDelegateCreator:Llyiahf/vczjk/gn;

    if-eqz v1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/f59;->_arrayDelegateArguments:[Llyiahf/vczjk/ph8;

    invoke-virtual {p0, v1, v0, p2, p1}, Llyiahf/vczjk/f59;->OooOoo(Llyiahf/vczjk/gn;[Llyiahf/vczjk/ph8;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/f59;->_delegateArguments:[Llyiahf/vczjk/ph8;

    invoke-virtual {p0, v0, v1, p2, p1}, Llyiahf/vczjk/f59;->OooOoo(Llyiahf/vczjk/gn;[Llyiahf/vczjk/ph8;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo0O()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_arrayDelegateType:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final OooOo0o()Llyiahf/vczjk/gn;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_defaultCreator:Llyiahf/vczjk/gn;

    return-object v0
.end method

.method public final OooOoO(Llyiahf/vczjk/t72;)[Llyiahf/vczjk/ph8;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/f59;->_constructorArguments:[Llyiahf/vczjk/ph8;

    return-object p1
.end method

.method public final OooOoO0()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_delegateType:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final OooOoOO()Llyiahf/vczjk/vm;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_incompleteParameter:Llyiahf/vczjk/vm;

    return-object v0
.end method

.method public final OooOoo(Llyiahf/vczjk/gn;[Llyiahf/vczjk/ph8;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    if-eqz p1, :cond_3

    if-nez p2, :cond_0

    :try_start_0
    invoke-virtual {p1, p4}, Llyiahf/vczjk/gn;->o0O0O00(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    array-length v0, p2

    new-array v1, v0, [Ljava/lang/Object;

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_2

    aget-object v3, p2, v2

    if-nez v3, :cond_1

    aput-object p4, v1, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    invoke-virtual {v3}, Llyiahf/vczjk/ph8;->OooOOO()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p3, p1}, Llyiahf/vczjk/v72;->ooOO(Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1

    :cond_2
    invoke-virtual {p1, v1}, Llyiahf/vczjk/gn;->oo0o0Oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object p1

    :goto_1
    invoke-virtual {p0, p3, p1}, Llyiahf/vczjk/f59;->OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string p3, "No delegate constructor for "

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object p3, p0, Llyiahf/vczjk/f59;->_valueTypeDesc:Ljava/lang/String;

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOoo0()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f59;->_valueClass:Ljava/lang/Class;

    return-object v0
.end method

.method public final OooOooO(Llyiahf/vczjk/v72;Ljava/lang/Throwable;)Llyiahf/vczjk/na4;
    .locals 1

    instance-of v0, p2, Ljava/lang/ExceptionInInitializerError;

    if-nez v0, :cond_0

    instance-of v0, p2, Ljava/lang/reflect/InvocationTargetException;

    if-eqz v0, :cond_1

    :cond_0
    invoke-virtual {p2}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_1

    move-object p2, v0

    :cond_1
    nop

    instance-of v0, p2, Llyiahf/vczjk/na4;

    if-eqz v0, :cond_2

    check-cast p2, Llyiahf/vczjk/na4;

    return-object p2

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/f59;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o00000oo(Ljava/lang/Class;Ljava/lang/Throwable;)Llyiahf/vczjk/lca;

    move-result-object p1

    return-object p1
.end method
