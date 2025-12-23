.class public final Llyiahf/vczjk/rv2;
.super Llyiahf/vczjk/m49;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _message:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    const-class v0, Ljava/lang/Object;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    const-string v0, "No _valueDeserializer assigned"

    iput-object v0, p0, Llyiahf/vczjk/rv2;->_message:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 1

    iget-object p2, p0, Llyiahf/vczjk/rv2;->_message:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    invoke-virtual {p1, p0, p2, v0}, Llyiahf/vczjk/v72;->o0000OO0(Llyiahf/vczjk/e94;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method
