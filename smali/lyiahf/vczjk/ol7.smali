.class public abstract Llyiahf/vczjk/ol7;
.super Llyiahf/vczjk/m49;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;


# static fields
.field private static final serialVersionUID:J = 0x2L


# instance fields
.field protected final _fullType:Llyiahf/vczjk/x64;

.field protected final _valueDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _valueInstantiator:Llyiahf/vczjk/nca;

.field protected final _valueTypeDeserializer:Llyiahf/vczjk/u3a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iput-object p4, p0, Llyiahf/vczjk/ol7;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object p1, p0, Llyiahf/vczjk/ol7;->_fullType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    iput-object p3, p0, Llyiahf/vczjk/ol7;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    return-void
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/o0OoO00O;
    .locals 1

    sget-object v0, Llyiahf/vczjk/o0OoO00O;->OooOOOO:Llyiahf/vczjk/o0OoO00O;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ol7;->_fullType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOO0()Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object p1

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/ol7;->_fullType:Llyiahf/vczjk/x64;

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooOO0()Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {p1, v0, p2, v1}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object p1

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p2}, Llyiahf/vczjk/u3a;->OooO0o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/u3a;

    move-result-object v0

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-ne p1, p2, :cond_2

    iget-object p2, p0, Llyiahf/vczjk/ol7;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-ne v0, p2, :cond_2

    return-object p0

    :cond_2
    move-object p2, p0

    check-cast p2, Llyiahf/vczjk/h10;

    new-instance v1, Llyiahf/vczjk/h10;

    iget-object v2, p2, Llyiahf/vczjk/ol7;->_fullType:Llyiahf/vczjk/x64;

    iget-object p2, p2, Llyiahf/vczjk/ol7;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-direct {v1, v2, p1, v0, p2}, Llyiahf/vczjk/ol7;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;)V

    return-object v1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueInstantiator:Llyiahf/vczjk/nca;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/ol7;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p2, p1, v0}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p1

    :goto_0
    new-instance p2, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {p2, p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    return-object p2
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    sget-object p3, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, p3}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result p3

    if-eqz p3, :cond_0

    move-object p1, p0

    check-cast p1, Llyiahf/vczjk/h10;

    new-instance p3, Ljava/util/concurrent/atomic/AtomicReference;

    iget-object p1, p1, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/e94;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    invoke-direct {p3, p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    return-object p3

    :cond_0
    iget-object p3, p0, Llyiahf/vczjk/ol7;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez p3, :cond_1

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/ol7;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    new-instance p2, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {p2, p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    return-object p2
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p2}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/e94;->OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;

    move-result-object v0

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-virtual {v0, v1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-eqz v0, :cond_0

    goto :goto_1

    :cond_0
    move-object v0, p3

    check-cast v0, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_2

    iget-object p3, p0, Llyiahf/vczjk/ol7;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez p3, :cond_1

    iget-object p3, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p1

    :goto_0
    new-instance p2, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {p2, p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    return-object p2

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p1, p2, v0}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_2

    :cond_3
    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_2

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p1, p2, v0}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p1

    :goto_2
    check-cast p3, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p3, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    return-object p3
.end method

.method public final OoooO()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ol7;->_fullType:Llyiahf/vczjk/x64;

    return-object v0
.end method
