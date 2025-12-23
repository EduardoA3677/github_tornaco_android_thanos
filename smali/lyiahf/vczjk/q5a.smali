.class public final Llyiahf/vczjk/q5a;
.super Llyiahf/vczjk/e94;
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

.field protected final _typeDeserializer:Llyiahf/vczjk/u3a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u3a;Llyiahf/vczjk/e94;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q5a;->_typeDeserializer:Llyiahf/vczjk/u3a;

    iput-object p2, p0, Llyiahf/vczjk/q5a;->_deserializer:Llyiahf/vczjk/e94;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q5a;->_deserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/e94;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/q5a;->_deserializer:Llyiahf/vczjk/e94;

    iget-object v1, p0, Llyiahf/vczjk/q5a;->_typeDeserializer:Llyiahf/vczjk/u3a;

    invoke-virtual {v0, p2, p1, v1}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Type-wrapped deserializer\'s deserializeWithType should never get called"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q5a;->_deserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q5a;->_deserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/e94;->OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0O()Ljava/util/Collection;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q5a;->_deserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0}, Llyiahf/vczjk/e94;->OooOO0O()Ljava/util/Collection;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOO0()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q5a;->_deserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0}, Llyiahf/vczjk/e94;->OooOOO0()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q5a;->_deserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/e94;->OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
