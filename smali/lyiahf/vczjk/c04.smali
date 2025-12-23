.class public final Llyiahf/vczjk/c04;
.super Llyiahf/vczjk/a69;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _inputType:Llyiahf/vczjk/gc4;

.field protected final _targetType:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/Class;Ljava/lang/String;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)V
    .locals 0

    invoke-direct {p0, p3, p2}, Llyiahf/vczjk/a69;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;)V

    iput-object p4, p0, Llyiahf/vczjk/c04;->_inputType:Llyiahf/vczjk/gc4;

    iput-object p1, p0, Llyiahf/vczjk/c04;->_targetType:Ljava/lang/Class;

    return-void
.end method
